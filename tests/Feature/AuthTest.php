<?php

namespace Tests\Feature;

use App\Models\Device;
use App\Models\OneTimeCode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class AuthTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        // Mock default risk engine response (safe allow)
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'risk_score' => 10,
                'risk_level' => 'LOW',
                'recommended_action' => 'ALLOW',
                'reasons' => [],
                'engine_version' => '1.0.0',
            ], 200),
        ]);
    }

    public function test_csrf_token_endpoint_returns_token(): void
    {
        $response = $this->getJson('/api/csrf-token');

        $response->assertStatus(200)
            ->assertJsonStructure(['status', 'csrf_token', 'message']);
    }

    public function test_login_requires_x_device_id_header(): void
    {
        $response = $this->postJson('/api/auth/login', [
            'login' => 'admin@ztp.local',
            'password' => 'AdminPassword123!',
        ]);

        $response->assertStatus(400)
            ->assertJsonFragment(['error_code' => 'DEVICE_IDENTIFIER_MISSING']);
    }

    public function test_login_fails_with_invalid_credentials(): void
    {
        $user = User::factory()->create([
            'email' => 'user@ztp.local',
            'password' => 'CorrectPassword123!',
        ]);

        $response = $this->withHeader('X-Device-Id', 'device-test-123')
            ->postJson('/api/auth/login', [
                'login' => 'user@ztp.local',
                'password' => 'WrongPassword',
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);

        $this->assertEquals(1, $user->fresh()->failed_login_attempts);
    }

    public function test_login_triggers_2fa_challenge_when_user_has_2fa_enabled(): void
    {
        $user = User::factory()->create([
            'email' => 'mfa-user@ztp.local',
            'password' => 'StrongPassword123!',
            'two_factor_enabled' => true,
        ]);

        $response = $this->withHeader('X-Device-Id', 'device-mfa-456')
            ->postJson('/api/auth/login', [
                'login' => 'mfa-user@ztp.local',
                'password' => 'StrongPassword123!',
            ]);

        $response->assertStatus(200)
            ->assertJsonFragment([
                'requires_2fa' => true,
                'user_id' => $user->id,
            ]);

        $this->assertDatabaseHas('one_time_codes', [
            'user_id' => $user->id,
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
        ]);
    }

    public function test_2fa_otp_verification_successfully_authenticates_user(): void
    {
        $user = User::factory()->create([
            'email' => 'verify@ztp.local',
            'two_factor_enabled' => true,
        ]);

        $plainCode = '123456';
        OneTimeCode::create([
            'user_id' => $user->id,
            'code_hash' => hash('sha256', $plainCode),
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
            'expires_at' => now()->addMinutes(10),
        ]);

        $response = $this->withHeader('X-Device-Id', 'device-verify-789')
            ->postJson('/api/auth/verify-otp', [
                'user_id' => $user->id,
                'code' => $plainCode,
            ]);

        $response->assertStatus(200)
            ->assertJsonFragment(['requires_2fa' => false])
            ->assertJsonPath('data.user.email', 'verify@ztp.local');

        $this->assertAuthenticatedAs($user, 'web');
    }

    public function test_login_rejected_for_blocked_device(): void
    {
        $user = User::factory()->create(['email' => 'victim@ztp.local']);
        Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'blocked-device-999',
            'is_blocked' => true,
        ]);

        $response = $this->withHeader('X-Device-Id', 'blocked-device-999')
            ->postJson('/api/auth/login', [
                'login' => 'victim@ztp.local',
                'password' => 'password',
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['device']);
    }

    public function test_authenticated_user_can_view_profile_and_logout(): void
    {
        $user = User::factory()->create(['email' => 'session@ztp.local']);

        $response = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'device-session-111')
            ->getJson('/api/auth/me');

        $response->assertStatus(200)
            ->assertJsonPath('data.email', 'session@ztp.local');

        $logoutResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'device-session-111')
            ->postJson('/api/auth/logout');

        $logoutResponse->assertStatus(200);
        $this->assertGuest('web');
    }

    public function test_login_from_untrusted_device_triggers_device_verification_challenge(): void
    {
        $user = User::factory()->create([
            'email' => 'newdevice@ztp.local',
            'password' => 'StrongPass123!',
            'two_factor_enabled' => false,
        ]);

        $response = $this->withHeader('X-Device-Id', 'unrecognized-device-999')
            ->postJson('/api/auth/login', [
                'login' => 'newdevice@ztp.local',
                'password' => 'StrongPass123!',
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.deviceVerificationRequired', true)
            ->assertJsonPath('data.requires_2fa', false)
            ->assertJsonPath('data.user_id', $user->id);
    }

    public function test_verify_device_authenticates_and_marks_device_as_trusted_and_returns_role(): void
    {
        $user = User::factory()->create([
            'email' => 'devicetrust@ztp.local',
            'type' => User::TYPE_ADMIN,
        ]);

        $plainCode = '654321';
        OneTimeCode::create([
            'user_id' => $user->id,
            'code_hash' => hash('sha256', $plainCode),
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
            'expires_at' => now()->addMinutes(10),
        ]);

        $response = $this->withHeader('X-Device-Id', 'trust-device-777')
            ->postJson('/api/auth/verify-device', [
                'email' => 'devicetrust@ztp.local',
                'code' => $plainCode,
                'rememberDevice' => true,
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.user.role', 'admin')
            ->assertJsonPath('data.user.type', 'admin');

        $this->assertDatabaseHas('devices', [
            'user_id' => $user->id,
            'device_identifier' => 'trust-device-777',
            'is_trusted' => true,
        ]);
    }

    public function test_auth_me_returns_both_type_and_role(): void
    {
        $admin = User::factory()->create([
            'email' => 'admin-me@ztp.local',
            'type' => User::TYPE_ADMIN,
        ]);

        $response = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', 'device-admin-me')
            ->getJson('/api/auth/me');

        $response->assertStatus(200)
            ->assertJsonPath('data.type', 'admin')
            ->assertJsonPath('data.role', 'admin');
    }
}
