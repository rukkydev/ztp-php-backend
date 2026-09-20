<?php

namespace Tests\Feature;

use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuditLogTest extends TestCase
{
    use RefreshDatabase;

    public function test_analyst_can_view_and_export_audit_trail(): void
    {
        $analyst = User::factory()->analyst()->create();

        AuditLog::create([
            'actor_id' => $analyst->id,
            'actor_username' => $analyst->username,
            'actor_type' => $analyst->type,
            'event_category' => 'AUTHENTICATION',
            'action' => 'LOGIN_SUCCESS',
            'description' => 'Analyst logged in successfully',
            'ip_address' => '127.0.0.1',
        ]);

        $indexResponse = $this->actingAs($analyst, 'web')
            ->withHeader('X-Device-Id', 'analyst-audit-dev1')
            ->getJson('/api/security/audit-logs');

        $indexResponse->assertStatus(200)
            ->assertJsonPath('data.data.0.action', 'LOGIN_SUCCESS');

        $exportResponse = $this->actingAs($analyst, 'web')
            ->withHeader('X-Device-Id', 'analyst-audit-dev1')
            ->getJson('/api/security/audit-logs/export');

        $exportResponse->assertStatus(200)
            ->assertJsonStructure(['status', 'data', 'count', 'exported_at']);
    }
}
