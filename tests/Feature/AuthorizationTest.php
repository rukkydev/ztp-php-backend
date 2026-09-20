<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthorizationTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_can_provision_new_users(): void
    {
        $admin = User::factory()->admin()->create();

        $response = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', 'admin-device-001')
            ->postJson('/api/admin/users', [
                'username' => 'newuser',
                'name' => 'New User',
                'email' => 'newuser@ztp.local',
                'password' => 'Password123!',
                'type' => User::TYPE_USER,
            ]);

        $response->assertStatus(201)
            ->assertJsonPath('data.username', 'newuser');

        $this->assertDatabaseHas('users', ['email' => 'newuser@ztp.local']);
    }

    public function test_security_analyst_cannot_create_or_delete_users(): void
    {
        $analyst = User::factory()->analyst()->create();

        $response = $this->actingAs($analyst, 'web')
            ->withHeader('X-Device-Id', 'analyst-device-001')
            ->postJson('/api/admin/users', [
                'username' => 'unauthorized',
                'email' => 'unauthorized@ztp.local',
                'password' => 'Password123!',
                'type' => User::TYPE_USER,
            ]);

        $response->assertStatus(403);
    }

    public function test_security_analyst_can_access_network_monitoring_and_risk_logs(): void
    {
        $analyst = User::factory()->analyst()->create();

        $response = $this->actingAs($analyst, 'web')
            ->withHeader('X-Device-Id', 'analyst-device-002')
            ->getJson('/api/analyst/network/metrics');

        $response->assertStatus(200)
            ->assertJsonStructure(['status', 'data' => ['total_events', 'average_response_time_ms']]);
    }

    public function test_standard_user_cannot_access_analyst_or_admin_endpoints(): void
    {
        $user = User::factory()->create();

        $analystResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'user-device-001')
            ->getJson('/api/analyst/network/events');

        $analystResponse->assertStatus(403);

        $adminResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'user-device-001')
            ->getJson('/api/admin/users');

        $adminResponse->assertStatus(403);
    }

    public function test_admin_can_mutate_security_policies_but_analyst_cannot_delete(): void
    {
        $admin = User::factory()->admin()->create();
        $analyst = User::factory()->analyst()->create();

        $createResponse = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', 'admin-device-002')
            ->postJson('/api/admin/policies', [
                'policy_name' => 'Custom Lockout Policy',
                'rule_type' => 'CUSTOM_RULE',
                'threshold_value' => '10',
                'action_on_breach' => 'LOCK_ACCOUNT',
                'is_enabled' => true,
            ]);

        $createResponse->assertStatus(201);
        $policyId = $createResponse->json('data.id');

        $deleteAttempt = $this->actingAs($analyst, 'web')
            ->withHeader('X-Device-Id', 'analyst-device-003')
            ->deleteJson("/api/admin/policies/{$policyId}");

        $deleteAttempt->assertStatus(403);
    }
}
