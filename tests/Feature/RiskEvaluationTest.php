<?php

namespace Tests\Feature;

use App\Models\Device;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use App\Services\RiskEvaluationClient;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
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

        $user = User::factory()->create();
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
        $this->assertDatabaseHas('risk_evaluation_logs', [
            'id' => $log->id,
            'evaluate_reached' => false,
        ]);
    }

    public function test_risk_evaluation_records_successful_analysis(): void
    {
        Http::fake([
            '*/risk/evaluate' => Http::response([
                'risk_score' => 85,
                'risk_level' => 'HIGH',
                'recommended_action' => 'BLOCK',
                'reasons' => ['geo_velocity_anomaly', 'unrecognized_device'],
                'engine_version' => '1.2.0',
            ], 200),
        ]);

        $user = User::factory()->create();
        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'high-risk-device',
            'is_trusted' => false,
        ]);

        $client = app(RiskEvaluationClient::class);
        $log = $client->evaluate($user, $device, 'LOGIN_ATTEMPT', ['ip_address' => '192.168.1.100']);

        $this->assertEquals(85, $log->risk_score);
        $this->assertEquals(RiskEvaluationLog::LEVEL_HIGH, $log->risk_level);
        $this->assertEquals(RiskEvaluationLog::ACTION_BLOCK, $log->recommended_action);
        $this->assertTrue($log->evaluate_reached);
        $this->assertEquals('1.2.0', $log->engine_version);
    }
}
