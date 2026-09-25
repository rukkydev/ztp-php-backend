<?php

namespace Tests\Feature;

use App\Models\Device;
use App\Models\OneTimeCode;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

class RealWorldSecuritySequencesTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        // Default mock for benign risk evaluation
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => (string) Str::uuid(),
                'risk_score' => 15,
                'risk_level' => 'LOW',
                'recommended_action' => 'ALLOW',
                'reasons' => ['baseline_access'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);
    }

    /**
     * Sequence 1: Missing Device Identifier Header.
     * Every zero-trust request must present hardware/client telemetry (X-Device-Id).
     */
    public function test_sequence_01_request_without_device_id_is_immediately_rejected(): void
    {
        $response = $this->postJson('/api/auth/login', [
            'login' => 'user@ztp.local',
            'password' => 'Password123!',
        ]);

        $response->assertStatus(400)
            ->assertJsonPath('status', 'error')
            ->assertJsonPath('error_code', 'DEVICE_IDENTIFIER_MISSING');
    }

    /**
     * Sequence 2: Login with Invalid Details (Non-Existent User).
     * Unknown identity attempting authentication triggers failed login audit record.
     */
    public function test_sequence_02_login_with_non_existent_email_fails_and_audits(): void
    {
        $response = $this->withHeader('X-Device-Id', 'device-seq-02')
            ->postJson('/api/auth/login', [
                'login' => 'nonexistent.attacker@evil.corp',
                'password' => 'HackedPassword123!',
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['login']);

        $this->assertDatabaseHas('audit_logs', [
            'actor_type' => 'guest',
            'action' => 'LOGIN_FAILED_UNKNOWN_USER',
        ]);
    }

    /**
     * Sequence 3: Valid User, Incorrect Password.
     * Verifies password failure increments failed login counter.
     */
    public function test_sequence_03_login_with_wrong_password_increments_failure_counter(): void
    {
        $user = User::factory()->create([
            'email' => 'victim@ztp.local',
            'password' => Hash::make('CorrectPassword123!'),
            'failed_login_attempts' => 0,
        ]);

        $response = $this->withHeader('X-Device-Id', 'device-seq-03')
            ->postJson('/api/auth/login', [
                'login' => 'victim@ztp.local',
                'password' => 'WrongPasswordOops!',
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['password']);

        // Failed attempts incremented to 1
        $this->assertEquals(1, $user->fresh()->failed_login_attempts);

        $this->assertDatabaseHas('audit_logs', [
            'actor_id' => $user->id,
            'action' => 'LOGIN_FAILED_BAD_PASSWORD',
        ]);
    }

    /**
     * Sequence 4: Automated Account Lockout Mitigation After 5 Consecutive Failures.
     * Simulates brute-force attack trigger.
     */
    public function test_sequence_04_brute_force_attack_triggers_automated_account_lockout(): void
    {
        $user = User::factory()->create([
            'email' => 'target@ztp.local',
            'password' => Hash::make('TargetPassword123!'),
            'failed_login_attempts' => 4, // 4 prior failures
            'account_locked' => false,
        ]);

        // 5th failed attempt
        $response = $this->withHeader('X-Device-Id', 'attacker-botnet-01')
            ->postJson('/api/auth/login', [
                'login' => 'target@ztp.local',
                'password' => 'FifthWrongPassword!',
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['account']);

        // Account is now locked in DB
        $freshUser = $user->fresh();
        $this->assertTrue($freshUser->account_locked);
        $this->assertNotNull($freshUser->locked_until);

        // Immediate subsequent attempt on locked account is rejected
        $blockedResponse = $this->withHeader('X-Device-Id', 'attacker-botnet-01')
            ->postJson('/api/auth/login', [
                'login' => 'target@ztp.local',
                'password' => 'TargetPassword123!',
            ]);

        $blockedResponse->assertStatus(422)
            ->assertJsonValidationErrors(['account']);

        $this->assertDatabaseHas('audit_logs', [
            'actor_id' => $user->id,
            'action' => 'LOCKED_ACCOUNT_REJECTED',
        ]);
    }

    /**
     * Sequence 5: Login from Unrecognized Device Triggers Step-Up Challenge.
     */
    public function test_sequence_05_unrecognized_device_triggers_verification_challenge(): void
    {
        $user = User::factory()->create([
            'email' => 'employee@ztp.local',
            'password' => Hash::make('ValidEmployeePass123!'),
            'two_factor_enabled' => false,
        ]);

        $newDeviceId = 'unrecognized-macbook-pro';

        $response = $this->withHeader('X-Device-Id', $newDeviceId)
            ->postJson('/api/auth/login', [
                'login' => 'employee@ztp.local',
                'password' => 'ValidEmployeePass123!',
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.deviceVerificationRequired', true)
            ->assertJsonPath('data.user_id', $user->id);

        // Unconsumed OTP code was generated in database
        $this->assertDatabaseHas('one_time_codes', [
            'user_id' => $user->id,
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
        ]);

        // User is still a guest
        $this->assertGuest('web');
    }

    /**
     * Sequence 6: Submitting Wrong Device Verification Code Fails.
     */
    public function test_sequence_06_submitting_incorrect_device_verification_code_fails(): void
    {
        $user = User::factory()->create([
            'email' => 'verify.test@ztp.local',
        ]);

        // Valid OTP in DB is '654321'
        OneTimeCode::create([
            'user_id' => $user->id,
            'code_hash' => hash('sha256', '654321'),
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
            'expires_at' => now()->addMinutes(10),
        ]);

        // User types incorrect code '111222'
        $response = $this->withHeader('X-Device-Id', 'verify-device-06')
            ->postJson('/api/auth/verify-device', [
                'email' => 'verify.test@ztp.local',
                'code' => '111222',
                'rememberDevice' => true,
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['code']);

        // User remains unauthenticated
        $this->assertGuest('web');

        // Audit log recorded the failed verification
        $this->assertDatabaseHas('audit_logs', [
            'actor_id' => $user->id,
            'action' => '2FA_VERIFICATION_FAILED',
        ]);
    }

    /**
     * Sequence 7: Submitting Correct Device Verification Code Authenticates & Trusts Device.
     */
    public function test_sequence_07_submitting_correct_code_authenticates_and_trusts_device(): void
    {
        $user = User::factory()->create([
            'email' => 'success.user@ztp.local',
            'two_factor_enabled' => false,
        ]);

        $deviceIdentifier = 'new-trusted-laptop-07';

        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => $deviceIdentifier,
            'device_name' => 'Dell Latitude 7420',
            'is_trusted' => false,
            'is_blocked' => false,
        ]);

        $validCode = '839201';
        OneTimeCode::create([
            'user_id' => $user->id,
            'code_hash' => hash('sha256', $validCode),
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
            'expires_at' => now()->addMinutes(10),
        ]);

        // Submit the correct code with rememberDevice = true
        $response = $this->withHeader('X-Device-Id', $deviceIdentifier)
            ->postJson('/api/auth/verify-device', [
                'email' => 'success.user@ztp.local',
                'code' => $validCode,
                'rememberDevice' => true,
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success')
            ->assertJsonPath('data.requires_2fa', false);

        // User is now authenticated
        $this->assertAuthenticatedAs($user, 'web');

        // Device is now marked trusted in DB
        $this->assertTrue($device->fresh()->is_trusted);

        // OTP is consumed
        $this->assertTrue(OneTimeCode::where('user_id', $user->id)->first()->consumed);

        // Success audit logged
        $this->assertDatabaseHas('audit_logs', [
            'actor_id' => $user->id,
            'action' => 'LOGIN_SUCCESS',
        ]);
    }

    /**
     * Sequence 8: Blocked Device Attempting Login is Blocked.
     */
    public function test_sequence_08_blocked_hardware_device_is_immediately_rejected(): void
    {
        $user = User::factory()->create([
            'email' => 'victim2@ztp.local',
            'password' => Hash::make('ValidPassword123!'),
        ]);

        Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'stolen-laptop-08',
            'is_trusted' => false,
            'is_blocked' => true, // Flagged stolen/compromised by SOC
        ]);

        $response = $this->withHeader('X-Device-Id', 'stolen-laptop-08')
            ->postJson('/api/auth/login', [
                'login' => 'victim2@ztp.local',
                'password' => 'ValidPassword123!',
            ]);

        $response->assertStatus(422)
            ->assertJsonValidationErrors(['device']);

        $this->assertGuest('web');
    }
}
