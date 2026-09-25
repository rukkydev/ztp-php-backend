<?php

namespace Tests\Feature;

use App\Models\Device;
use App\Models\ResponseAction;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use App\Services\AuthService;
use App\Services\RiskEvaluationClient;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Validation\ValidationException;
use Tests\TestCase;

class RiskEvaluationTest extends TestCase
{
    use RefreshDatabase;

    public function test_risk_evaluation_fails_open_when_microservice_times_out(): void
    {
        Http::fake([
            '*/risk/evaluate' => function () {
                throw new ConnectionException('Connection timed out after 400ms');
            },
        ]);

        $user = User::factory()->create(['username' => 'timeout_user']);
        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'timeout-device-1',
            'is_trusted' => false,
        ]);

        $client = app(RiskEvaluationClient::class);
        $log = $client->evaluate($user, $device, 'LOGIN_ATTEMPT', ['ip_address' => '127.0.0.1']);

        $this->assertInstanceOf(RiskEvaluationLog::class, $log);
        $this->assertEquals(0, $log->risk_score);
        $this->assertEquals(RiskEvaluationLog::LEVEL_LOW, $log->risk_level);
        $this->assertEquals(RiskEvaluationLog::ACTION_ALLOW, $log->recommended_action);
        $this->assertFalse($log->evaluate_reached);
        $this->assertEquals('1.0.0', $log->engine_version);
        $this->assertContains('engine_fail_open_timeout', $log->reasons_json);
        $this->assertEquals('timeout_user', $log->username);
        $this->assertNotNull($log->latency_ms);

        $this->assertDatabaseHas('risk_evaluation_logs', [
            'id' => $log->id,
            'evaluate_reached' => false,
            'username' => 'timeout_user',
        ]);
    }

    public function test_risk_evaluation_fails_open_when_disabled_via_config(): void
    {
        Config::set('services.risk_engine.enabled', false);

        $user = User::factory()->create(['username' => 'disabled_user']);
        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'disabled-device-1',
            'is_trusted' => false,
        ]);

        $client = app(RiskEvaluationClient::class);
        $log = $client->evaluate($user, $device, 'LOGIN_ATTEMPT', ['ip_address' => '127.0.0.1']);

        $this->assertEquals(0, $log->risk_score);
        $this->assertEquals(RiskEvaluationLog::LEVEL_LOW, $log->risk_level);
        $this->assertEquals(RiskEvaluationLog::ACTION_ALLOW, $log->recommended_action);
        $this->assertFalse($log->evaluate_reached);
        $this->assertContains('engine_disabled', $log->reasons_json);
    }

    public function test_risk_evaluation_records_successful_analysis(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => 'custom-corr-123',
                'risk_score' => 85,
                'risk_level' => 'HIGH',
                'recommended_action' => 'BLOCK',
                'reasons' => ['geo_velocity_anomaly', 'unrecognized_device'],
                'engine_version' => '1.2.0',
            ], 200),
        ]);

        $user = User::factory()->create(['username' => 'analyst_test_user']);
        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'high-risk-device',
            'is_trusted' => false,
        ]);

        $client = app(RiskEvaluationClient::class);
        $log = $client->evaluate($user, $device, 'LOGIN_ATTEMPT', [
            'ip_address' => '192.168.1.100',
            'correlation_id' => 'custom-corr-123',
        ]);

        $this->assertEquals('custom-corr-123', $log->correlation_id);
        $this->assertEquals(85, $log->risk_score);
        $this->assertEquals(RiskEvaluationLog::LEVEL_HIGH, $log->risk_level);
        $this->assertEquals(RiskEvaluationLog::ACTION_BLOCK, $log->recommended_action);
        $this->assertTrue($log->evaluate_reached);
        $this->assertEquals('1.2.0', $log->engine_version);
        $this->assertEquals('analyst_test_user', $log->username);
        $this->assertNotNull($log->latency_ms);
        $this->assertContains('geo_velocity_anomaly', $log->reasons_json);

        $this->assertDatabaseHas('risk_evaluation_logs', [
            'id' => $log->id,
            'correlation_id' => 'custom-corr-123',
            'username' => 'analyst_test_user',
            'evaluate_reached' => true,
        ]);
    }

    public function test_risk_evaluation_with_array_params_and_raw_output(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => 'array-corr-999',
                'risk_score' => 72,
                'risk_level' => 'HIGH',
                'recommended_action' => 'RESTRICT',
                'reasons' => ['untrusted_hardware_device', 'remote_public_ip_source'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create(['username' => 'johndoe']);

        $client = app(RiskEvaluationClient::class);
        $raw = $client->evaluateRaw([
            'correlation_id' => 'array-corr-999',
            'user_id' => $user->id,
            'username' => 'johndoe',
            'user_type' => 'user',
            'ip_address' => '198.51.100.45',
            'event_type' => 'LOGIN_ATTEMPT',
            'context' => ['failed_attempts' => 2],
        ]);

        $this->assertIsArray($raw);
        $this->assertEquals('array-corr-999', $raw['correlation_id']);
        $this->assertEquals(72, $raw['risk_score']);
        $this->assertEquals('HIGH', $raw['risk_level']);
        $this->assertEquals('RESTRICT', $raw['recommended_action']);
        $this->assertTrue($raw['evaluate_reached']);
        $this->assertContains('untrusted_hardware_device', $raw['reasons']);
    }

    public function test_health_and_readiness_probes(): void
    {
        Http::fake([
            '*/health' => Http::response([
                'status' => 'ok',
                'service' => 'risk-engine',
                'version' => '1.0.0',
            ], 200),
            '*/ready' => Http::response([
                'status' => 'ready',
                'model_loaded' => true,
            ], 200),
        ]);

        $client = app(RiskEvaluationClient::class);

        $health = $client->health();
        $this->assertEquals('ok', $health['status']);
        $this->assertTrue($client->isHealthy());

        $ready = $client->ready();
        $this->assertEquals('ready', $ready['status']);
        $this->assertTrue($ready['model_loaded']);
        $this->assertTrue($client->isReady());
    }

    public function test_login_enforces_block_action_by_isolating_device_and_terminating_session(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => 'block-corr-777',
                'risk_score' => 95,
                'risk_level' => 'CRITICAL',
                'recommended_action' => 'BLOCK',
                'reasons' => ['device_already_flagged_malicious', 'ml_behavioral_anomaly'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'target@ztp.local',
            'password' => 'SecurePass123!',
        ]);

        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'device-to-block-1',
            'is_trusted' => false,
            'is_blocked' => false,
        ]);

        // Create an existing session in database for this user
        DB::table('sessions')->insert([
            'id' => 'existing-session-token-1',
            'user_id' => $user->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'TestAgent',
            'payload' => 'payload',
            'last_activity' => time(),
        ]);

        $authService = app(AuthService::class);
        $request = Request::create('/api/auth/login', 'POST', [], [], [], [
            'HTTP_X_DEVICE_ID' => 'device-to-block-1',
            'REMOTE_ADDR' => '198.51.100.45',
        ]);

        $this->expectException(ValidationException::class);

        try {
            $authService->attemptLogin('target@ztp.local', 'SecurePass123!', $request);
        } catch (ValidationException $e) {
            // Verify device is isolated/blocked in database
            $this->assertTrue($device->fresh()->is_blocked);

            // Verify active sessions for this user were terminated
            $this->assertDatabaseMissing('sessions', ['user_id' => $user->id]);

            // Verify response action was logged with correlation ID
            $this->assertDatabaseHas('response_actions', [
                'correlation_id' => 'block-corr-777',
                'target_type' => ResponseAction::TARGET_DEVICE,
                'target_identifier' => 'device-to-block-1',
                'action_taken' => ResponseAction::ACTION_BLOCK_DEVICE,
            ]);

            // Verify audit log recorded security incident
            $this->assertDatabaseHas('audit_logs', [
                'actor_id' => $user->id,
                'action' => 'LOGIN_BLOCKED_BY_RISK_ENGINE',
                'correlation_id' => 'block-corr-777',
            ]);

            throw $e;
        }
    }

    public function test_login_enforces_restrict_action_by_locking_account(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'correlation_id' => 'restrict-corr-888',
                'risk_score' => 75,
                'risk_level' => 'HIGH',
                'recommended_action' => 'RESTRICT',
                'reasons' => ['velocity_impossible_travel'],
                'engine_version' => '1.0.0',
            ], 200),
        ]);

        $user = User::factory()->create([
            'email' => 'restrict-target@ztp.local',
            'password' => 'SecurePass123!',
            'account_locked' => false,
        ]);

        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'device-restrict-1',
            'is_trusted' => true,
            'is_blocked' => false,
        ]);

        $authService = app(AuthService::class);
        $request = Request::create('/api/auth/login', 'POST', [], [], [], [
            'HTTP_X_DEVICE_ID' => 'device-restrict-1',
            'REMOTE_ADDR' => '198.51.100.45',
        ]);

        $this->expectException(ValidationException::class);

        try {
            $authService->attemptLogin('restrict-target@ztp.local', 'SecurePass123!', $request);
        } catch (ValidationException $e) {
            // Verify user account is locked
            $this->assertTrue($user->fresh()->account_locked);

            // Verify response action was logged with correlation ID
            $this->assertDatabaseHas('response_actions', [
                'correlation_id' => 'restrict-corr-888',
                'target_type' => ResponseAction::TARGET_USER,
                'target_identifier' => (string) $user->id,
                'action_taken' => ResponseAction::ACTION_LOCK_ACCOUNT,
            ]);

            // Verify audit log recorded security incident
            $this->assertDatabaseHas('audit_logs', [
                'actor_id' => $user->id,
                'action' => 'LOGIN_RESTRICTED_BY_RISK_ENGINE',
                'correlation_id' => 'restrict-corr-888',
            ]);

            throw $e;
        }
    }
}
