<?php

namespace Tests\Feature;

use App\Models\Device;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class FrontendIntegrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_admin_can_access_reports_roles_settings_and_monitoring(): void
    {
        $admin = User::factory()->create(['type' => User::TYPE_ADMIN]);
        $deviceId = 'dev-admin-test-01';

        // 1. Reports
        $reportsList = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/admin/reports');
        $reportsList->assertStatus(200)
            ->assertJsonPath('status', 'success');

        $createReport = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->postJson('/api/admin/reports', ['type' => 'Compliance']);
        $createReport->assertStatus(201)
            ->assertJsonPath('data.type', 'Compliance');

        $downloadReport = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->get('/api/admin/reports/1/download');
        $downloadReport->assertStatus(200)
            ->assertHeader('Content-Type', 'text/csv; charset=UTF-8');

        // 2. Roles
        $rolesList = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/admin/roles');
        $rolesList->assertStatus(200)
            ->assertJsonPath('status', 'success');

        $patchRole = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->patchJson('/api/admin/roles/security-analyst', [
                'permissions' => ['View all activity logs', 'Manage alerts & threats'],
            ]);
        $patchRole->assertStatus(200);

        // 3. Settings
        $settingsGet = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/admin/settings');
        $settingsGet->assertStatus(200)
            ->assertJsonPath('data.general.orgName', 'Zero-Trust Security Operations');

        $settingsPatch = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->patchJson('/api/admin/settings', [
                'general' => ['orgName' => 'Updated Acme Security'],
            ]);
        $settingsPatch->assertStatus(200)
            ->assertJsonPath('data.general.orgName', 'Updated Acme Security');

        // 4. Network Monitoring Overview
        $monitoringGet = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/admin/network-monitoring');
        $monitoringGet->assertStatus(200)
            ->assertJsonStructure(['data' => ['stats', 'trafficTimeline', 'endpoints']]);

        // 5. Anomaly Detection Overview
        $anomalyGet = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/admin/anomaly-detection');
        $anomalyGet->assertStatus(200)
            ->assertJsonStructure(['data' => ['stats', 'timeline', 'anomalies']]);
    }

    public function test_alerts_and_threats_resolution_and_mitigation(): void
    {
        $admin = User::factory()->create(['type' => User::TYPE_ADMIN]);
        $deviceId = 'dev-admin-test-02';

        $riskLog1 = RiskEvaluationLog::create([
            'correlation_id' => 'corr-test-01',
            'user_id' => $admin->id,
            'event_type' => 'SUSPICIOUS_LOGIN',
            'risk_score' => 85,
            'risk_level' => 'HIGH',
            'recommended_action' => 'BLOCK',
            'ip_address' => '10.0.0.1',
            'evaluated_at' => now(),
        ]);

        $riskLog2 = RiskEvaluationLog::create([
            'correlation_id' => 'corr-test-02',
            'user_id' => $admin->id,
            'event_type' => 'IMPOSSIBLE_TRAVEL',
            'risk_score' => 92,
            'risk_level' => 'CRITICAL',
            'recommended_action' => 'BLOCK',
            'ip_address' => '10.0.0.2',
            'evaluated_at' => now(),
        ]);

        // Alert resolve
        $resolveRes = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->patchJson("/api/admin/alerts/{$riskLog1->id}");
        $resolveRes->assertStatus(200);
        $this->assertEquals('RESOLVED', $riskLog1->fresh()->enforced_action);

        // Bulk resolve
        $bulkResolve = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->patchJson('/api/admin/alerts/bulk-resolve', ['ids' => [$riskLog2->id]]);
        $bulkResolve->assertStatus(200);
        $this->assertEquals('RESOLVED', $riskLog2->fresh()->enforced_action);

        // Threat mitigate
        $mitigateRes = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->patchJson("/api/admin/threats/{$riskLog1->id}");
        $mitigateRes->assertStatus(200);
        $this->assertEquals('MITIGATED', $riskLog1->fresh()->enforced_action);
    }

    public function test_account_self_service_endpoints(): void
    {
        $user = User::factory()->create(['type' => User::TYPE_USER]);
        $deviceId = 'dev-user-test-01';

        Device::create([
            'user_id' => $user->id,
            'device_identifier' => $deviceId,
            'is_trusted' => true,
        ]);

        // 1. Account overview
        $overview = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/account/overview');
        $overview->assertStatus(200)
            ->assertJsonPath('status', 'success')
            ->assertJsonPath('data.deviceCount', 1);

        // 2. Recovery phrase status and generation
        $phraseStatus = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/account/security/recovery-phrase/status');
        $phraseStatus->assertStatus(200)
            ->assertJsonPath('data', false);

        $genPhrase = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->postJson('/api/account/security/recovery-phrase/generate');
        $genPhrase->assertStatus(200)
            ->assertJsonStructure(['data']);

        $this->assertNotEmpty($user->fresh()->recovery_phrase_hash);

        // 3. Notifications & preferences
        $notifs = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/account/notifications');
        $notifs->assertStatus(200);

        $unread = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/account/notifications/unread-count');
        $unread->assertStatus(200)
            ->assertJsonPath('data.count', 0);

        $markAll = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->patchJson('/api/account/notifications/read-all');
        $markAll->assertStatus(200);

        $prefs = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->getJson('/api/account/notification-preferences');
        $prefs->assertStatus(200);

        $savePrefs = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->patchJson('/api/account/notification-preferences', ['email' => []]);
        $savePrefs->assertStatus(200);

        // 4. Avatar upload
        Storage::fake('public');
        $file = UploadedFile::fake()->create('avatar.jpg', 100, 'image/jpeg');
        $avatarRes = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', $deviceId)
            ->postJson('/api/account/profile/avatar', ['file' => $file]);
        $avatarRes->assertStatus(200)
            ->assertJsonStructure(['data' => ['avatarUrl']]);
    }

    public function test_recovery_with_phrase_via_email(): void
    {
        $user = User::factory()->create([
            'email' => 'recoverme@ztp.local',
            'account_locked' => true,
        ]);

        $phrase = 'apple banana cherry date elderberry fig grape honeydew kiwi lemon mango nectarine';
        $user->update(['recovery_phrase_hash' => hash('sha256', $phrase)]);

        $response = $this->postJson('/api/auth/recover-with-phrase', [
            'email' => 'recoverme@ztp.local',
            'phrase' => $phrase,
            'newPassword' => 'NewSecurePass123!',
        ]);

        $response->assertStatus(200)
            ->assertJsonPath('status', 'success');

        $this->assertFalse($user->fresh()->account_locked);
    }
}
