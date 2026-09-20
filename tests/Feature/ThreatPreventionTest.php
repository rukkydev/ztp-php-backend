<?php

namespace Tests\Feature;

use App\Models\Device;
use App\Models\ResponseAction;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

class ThreatPreventionTest extends TestCase
{
    use RefreshDatabase;

    public function test_analyst_can_trigger_manual_device_blocking_mitigation(): void
    {
        $analyst = User::factory()->analyst()->create();
        $targetUser = User::factory()->create();
        $device = Device::create([
            'user_id' => $targetUser->id,
            'device_identifier' => 'threat-device-99',
            'is_blocked' => false,
        ]);

        $response = $this->actingAs($analyst, 'web')
            ->withHeader('X-Device-Id', 'analyst-device-10')
            ->postJson('/api/analyst/threat-responses/mitigate', [
                'target_type' => ResponseAction::TARGET_DEVICE,
                'target_identifier' => 'threat-device-99',
                'action' => ResponseAction::ACTION_BLOCK_DEVICE,
                'reason' => 'Anomalous exfiltration activity detected',
            ]);

        $response->assertStatus(200)
            ->assertJsonPath('data.action_taken', ResponseAction::ACTION_BLOCK_DEVICE);

        $this->assertTrue($device->fresh()->is_blocked);
        $this->assertDatabaseHas('response_actions', [
            'target_type' => ResponseAction::TARGET_DEVICE,
            'target_identifier' => 'threat-device-99',
            'action_taken' => ResponseAction::ACTION_BLOCK_DEVICE,
        ]);
    }

    public function test_analyst_can_revert_mitigation_action(): void
    {
        $analyst = User::factory()->analyst()->create();
        $targetUser = User::factory()->locked()->create();

        $action = ResponseAction::create([
            'correlation_id' => (string) Str::uuid(),
            'target_type' => ResponseAction::TARGET_USER,
            'target_identifier' => (string) $targetUser->id,
            'action_taken' => ResponseAction::ACTION_LOCK_ACCOUNT,
            'status' => ResponseAction::STATUS_EXECUTED,
            'executed_at' => now(),
        ]);

        $response = $this->actingAs($analyst, 'web')
            ->withHeader('X-Device-Id', 'analyst-device-11')
            ->postJson("/api/analyst/threat-responses/actions/{$action->id}/revert");

        $response->assertStatus(200)
            ->assertJsonPath('data.status', ResponseAction::STATUS_REVERTED);

        $this->assertFalse($targetUser->fresh()->account_locked);
    }
}
