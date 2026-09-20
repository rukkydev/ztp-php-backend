<?php

namespace Tests\Feature;

use App\Models\SecurityPolicy;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class PolicyManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_can_list_and_filter_security_policies(): void
    {
        $admin = User::factory()->admin()->create();
        SecurityPolicy::create([
            'policy_name' => 'Test Policy 1',
            'rule_type' => 'RULE_1',
            'threshold_value' => '10',
            'action_on_breach' => 'LOCK_ACCOUNT',
            'is_enabled' => true,
        ]);
        SecurityPolicy::create([
            'policy_name' => 'Test Policy 2',
            'rule_type' => 'RULE_2',
            'threshold_value' => '20',
            'action_on_breach' => 'BLOCK_DEVICE',
            'is_enabled' => false,
        ]);

        $response = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', 'admin-device-p1')
            ->getJson('/api/admin/policies?is_enabled=1');

        $response->assertStatus(200)
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.policy_name', 'Test Policy 1');
    }

    public function test_admin_can_toggle_policy_enabled_status(): void
    {
        $admin = User::factory()->admin()->create();
        $policy = SecurityPolicy::create([
            'policy_name' => 'Toggle Policy',
            'rule_type' => 'TOGGLE_RULE',
            'threshold_value' => '5',
            'action_on_breach' => 'MFA_CHALLENGE',
            'is_enabled' => true,
        ]);

        $response = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', 'admin-device-p2')
            ->postJson("/api/admin/policies/{$policy->id}/toggle");

        $response->assertStatus(200)
            ->assertJsonPath('data.is_enabled', false);

        $this->assertFalse($policy->fresh()->is_enabled);
    }
}
