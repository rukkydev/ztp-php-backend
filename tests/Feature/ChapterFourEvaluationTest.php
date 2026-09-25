<?php

namespace Tests\Feature;

use App\Models\AuditLog;
use App\Models\Device;
use App\Models\OneTimeCode;
use App\Models\RiskEvaluationLog;
use App\Models\SecurityPolicy;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

class ChapterFourEvaluationTest extends TestCase
{
    use RefreshDatabase;

    /**
     * TC01: Login with valid credentials from known/trusted device.
     * Expected: Direct access granted, session established, status 200 OK.
     */
    public function test_tc01_login_with_valid_credentials_from_known_trusted_device(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => (string) Str::uuid(),
                'risk_score' => 12,
                'risk_level' => 'LOW',
                'recommended_action' => 'ALLOW',
                'reasons' => ['trusted_device_match', 'baseline_behavior'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'alice@ztp.local',
            'password' => Hash::make('CorporatePassword123!'),
            'two_factor_enabled' => false,
        ]);

        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'trusted-workstation-tc01',
            'device_name' => 'Corporate ThinkPad X1',
            'is_trusted' => true,
            'is_blocked' => false,
        ]);

        $response = $this->withHeader('X-Device-Id', $device->device_identifier)
            ->postJson('/api/auth/login', [
                'login' => 'alice@ztp.local',
                'password' => 'CorporatePassword123!',
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success')
            ->assertJsonPath('data.user.email', 'alice@ztp.local')
            ->assertJsonPath('data.requires_2fa', false);

        $this->assertAuthenticatedAs($user, 'web');
    }

    /**
     * TC02: Attempt login from unrecognized device and show device verification/2FA triggered.
     * Expected: Step-up challenge initiated, deviceVerificationRequired is true, OTP dispatched.
     */
    public function test_tc02_attempt_login_from_unrecognized_device_triggers_device_verification(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => (string) Str::uuid(),
                'risk_score' => 45,
                'risk_level' => 'MEDIUM',
                'recommended_action' => 'CHALLENGE',
                'reasons' => ['unrecognized_hardware_device'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'bob@ztp.local',
            'password' => Hash::make('CorporatePassword123!'),
            'two_factor_enabled' => false,
        ]);

        $unrecognizedDeviceId = 'foreign-device-'.Str::random(12);

        $response = $this->withHeader('X-Device-Id', $unrecognizedDeviceId)
            ->postJson('/api/auth/login', [
                'login' => 'bob@ztp.local',
                'password' => 'CorporatePassword123!',
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.deviceVerificationRequired', true)
            ->assertJsonPath('data.user_id', $user->id);

        // Confirm OTP record was created for device verification challenge
        $this->assertDatabaseHas('one_time_codes', [
            'user_id' => $user->id,
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
        ]);

        // User must not be authenticated until OTP is verified
        $this->assertGuest('web');
    }

    /**
     * TC03: Test an ALLOW risk decision, confirm access granted, and session created.
     * Expected: Risk Engine returns ALLOW, HTTP 200 OK, session created.
     */
    public function test_tc03_test_allow_risk_decision_grants_access_and_creates_session(): void
    {
        $corrId = (string) Str::uuid();

        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => $corrId,
                'risk_score' => 8,
                'risk_level' => 'LOW',
                'recommended_action' => 'ALLOW',
                'reasons' => ['low_risk_baseline', 'verified_subnet'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'charlie@ztp.local',
            'password' => Hash::make('SecurePassword123!'),
            'two_factor_enabled' => false,
        ]);

        Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'workstation-tc03',
            'is_trusted' => true,
            'is_blocked' => false,
        ]);

        $response = $this->withHeader('X-Device-Id', 'workstation-tc03')
            ->postJson('/api/auth/login', [
                'login' => 'charlie@ztp.local',
                'password' => 'SecurePassword123!',
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success');

        $this->assertAuthenticatedAs($user, 'web');

        // Confirm risk evaluation was recorded with ALLOW
        $this->assertDatabaseHas('risk_evaluation_logs', [
            'correlation_id' => $corrId,
            'recommended_action' => 'ALLOW',
            'risk_level' => 'LOW',
        ]);
    }

    /**
     * TC04: Test a CHALLENGE decision and confirm 2FA required.
     * Expected: Risk Engine returns CHALLENGE, step-up MFA is enforced.
     */
    public function test_tc04_test_challenge_risk_decision_requires_step_up_2fa(): void
    {
        $corrId = (string) Str::uuid();

        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => $corrId,
                'risk_score' => 60,
                'risk_level' => 'MEDIUM',
                'recommended_action' => 'CHALLENGE',
                'reasons' => ['geo_velocity_elevation', 'off_hours_access'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'david@ztp.local',
            'password' => Hash::make('SecurePassword123!'),
            'two_factor_enabled' => true,
        ]);

        Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'device-tc04',
            'is_trusted' => true,
            'is_blocked' => false,
        ]);

        $response = $this->withHeader('X-Device-Id', 'device-tc04')
            ->postJson('/api/auth/login', [
                'login' => 'david@ztp.local',
                'password' => 'SecurePassword123!',
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.requires_2fa', true)
            ->assertJsonPath('data.user_id', $user->id);

        $this->assertDatabaseHas('one_time_codes', [
            'user_id' => $user->id,
            'purpose' => OneTimeCode::PURPOSE_LOGIN_2FA,
            'consumed' => false,
        ]);

        $this->assertGuest('web');
    }

    /**
     * TC05: Test a RESTRICT/BLOCK decision and confirm access restricted/blocked.
     * Expected: Risk Engine returns BLOCK or RESTRICT, HTTP 422 security rejection, access blocked.
     */
    public function test_tc05_test_restrict_or_block_decision_restricts_and_blocks_access(): void
    {
        $blockCorrId = (string) Str::uuid();

        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => $blockCorrId,
                'risk_score' => 95,
                'risk_level' => 'CRITICAL',
                'recommended_action' => 'BLOCK',
                'reasons' => ['ml_isolation_forest_anomaly', 'impossible_travel', 'malicious_ip_reputation'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'eve@ztp.local',
            'password' => Hash::make('SecurePassword123!'),
        ]);

        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'compromised-laptop-tc05',
            'is_trusted' => false,
            'is_blocked' => false,
        ]);

        $response = $this->withHeader('X-Device-Id', $device->device_identifier)
            ->postJson('/api/auth/login', [
                'login' => 'eve@ztp.local',
                'password' => 'SecurePassword123!',
            ]);

        // Access must be rejected with validation error regarding device block
        $response->assertStatus(422)
            ->assertJsonValidationErrors(['device']);

        // Assert device has been automatically mitigated and blocked in database
        $this->assertTrue($device->fresh()->is_blocked);

        // Assert user remains unauthenticated
        $this->assertGuest('web');

        // Assert audit trail captured the block event
        $this->assertDatabaseHas('audit_logs', [
            'action' => 'LOGIN_BLOCKED_BY_RISK_ENGINE',
            'correlation_id' => $blockCorrId,
        ]);
    }

    /**
     * TC06: Log in successfully and confirm session actually persisted.
     * Expected: Login succeeds, session persists, subsequent authenticated requests to /api/auth/me succeed.
     */
    public function test_tc06_successful_login_persists_session_and_enables_authenticated_access(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => (string) Str::uuid(),
                'risk_score' => 10,
                'risk_level' => 'LOW',
                'recommended_action' => 'ALLOW',
                'reasons' => [],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'frank@ztp.local',
            'password' => Hash::make('SecurePassword123!'),
        ]);

        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'frank-pc-tc06',
            'is_trusted' => true,
            'is_blocked' => false,
        ]);

        $loginResponse = $this->withHeader('X-Device-Id', $device->device_identifier)
            ->postJson('/api/auth/login', [
                'login' => 'frank@ztp.local',
                'password' => 'SecurePassword123!',
            ]);

        $loginResponse->assertStatus(200);

        // Access authenticated endpoint using session
        $meResponse = $this->withHeader('X-Device-Id', $device->device_identifier)
            ->getJson('/api/auth/me');

        $meResponse->assertStatus(200)
            ->assertJsonPath('data.email', 'frank@ztp.local');

        $this->assertAuthenticatedAs($user, 'web');
    }

    /**
     * TC07: Perform a security event and show audit record and risk evaluation share the same correlation ID.
     * Expected: $riskLog->correlation_id === $auditLog->correlation_id.
     */
    public function test_tc07_security_event_shares_identical_correlation_id_across_audit_and_risk_evaluation(): void
    {
        $uniqueCorrelationId = 'corr-ztp-'.Str::uuid();

        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => $uniqueCorrelationId,
                'risk_score' => 78,
                'risk_level' => 'HIGH',
                'recommended_action' => 'RESTRICT',
                'reasons' => ['credential_stuffing_pattern', 'velocity_threshold_exceeded'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'grace@ztp.local',
            'password' => Hash::make('SecurePassword123!'),
        ]);

        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'grace-dev-tc07',
            'is_trusted' => false,
        ]);

        $response = $this->withHeader('X-Device-Id', $device->device_identifier)
            ->postJson('/api/auth/login', [
                'login' => 'grace@ztp.local',
                'password' => 'SecurePassword123!',
            ]);

        $response->assertStatus(422);

        // Fetch corresponding RiskEvaluationLog and AuditLog
        $riskLog = RiskEvaluationLog::where('correlation_id', $uniqueCorrelationId)->first();
        $auditLog = AuditLog::where('correlation_id', $uniqueCorrelationId)->first();

        $this->assertNotNull($riskLog, 'RiskEvaluationLog must exist with correlation ID');
        $this->assertNotNull($auditLog, 'AuditLog must exist with correlation ID');

        // Confirm exact match between Risk Evaluation and Audit Trail
        $this->assertEquals($riskLog->correlation_id, $auditLog->correlation_id);
        $this->assertEquals($uniqueCorrelationId, $auditLog->correlation_id);
    }

    /**
     * TC08: Perform admin action, confirm permission checked (RBAC), and action recorded in audit trail.
     * Expected: Standard user rejected with 403; Admin user accepted with 200, action logged.
     */
    public function test_tc08_admin_action_enforces_rbac_and_records_audit_trail(): void
    {
        $standardUser = User::factory()->create([
            'type' => User::TYPE_USER,
        ]);

        $adminUser = User::factory()->admin()->create();

        $policy = SecurityPolicy::create([
            'policy_name' => 'Require MFA on Elevated Risk',
            'description' => 'Trigger step-up authentication when risk score exceeds 40',
            'rule_type' => SecurityPolicy::RULE_RISK_SCORE_THRESHOLD,
            'threshold_value' => '40',
            'action_on_breach' => SecurityPolicy::ACTION_MFA_CHALLENGE,
            'is_enabled' => true,
        ]);

        // 1. Standard user attempts admin-restricted action (toggle policy)
        $unauthorizedResponse = $this->actingAs($standardUser, 'web')
            ->withHeader('X-Device-Id', 'user-laptop-tc08')
            ->postJson("/api/admin/policies/{$policy->id}/toggle");

        $unauthorizedResponse->assertStatus(403);

        // 2. Admin performs the authorized action
        $authorizedResponse = $this->actingAs($adminUser, 'web')
            ->withHeader('X-Device-Id', 'admin-workstation-tc08')
            ->postJson("/api/admin/policies/{$policy->id}/toggle");

        $authorizedResponse->assertStatus(200);

        // 3. Confirm policy status was toggled
        $this->assertFalse($policy->fresh()->is_enabled);

        // 4. Confirm audit log recorded the administrative action
        $this->assertDatabaseHas('audit_logs', [
            'actor_id' => $adminUser->id,
            'actor_type' => User::TYPE_ADMIN,
            'event_category' => 'POLICY',
            'action' => 'POLICY_TOGGLED',
        ]);
    }
}
