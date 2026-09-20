<?php

namespace Tests\Feature;

use App\Models\Device;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class UserDeviceManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_user_can_update_profile_and_toggle_two_factor(): void
    {
        $user = User::factory()->create([
            'name' => 'Original Name',
            'two_factor_enabled' => false,
        ]);

        $profileResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'user-device-dev1')
            ->putJson('/api/user/profile', [
                'name' => 'Updated Name',
                'department' => 'Cybersecurity',
                'job_title' => 'Security Architect',
            ]);

        $profileResponse->assertStatus(200)
            ->assertJsonPath('data.name', 'Updated Name')
            ->assertJsonPath('data.department', 'Cybersecurity');

        $twoFactorResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'user-device-dev1')
            ->postJson('/api/user/two-factor/toggle', [
                'enabled' => true,
            ]);

        $twoFactorResponse->assertStatus(200)
            ->assertJsonPath('two_factor_enabled', true);

        $this->assertTrue($user->fresh()->two_factor_enabled);
    }

    public function test_user_can_trust_and_revoke_registered_devices(): void
    {
        $user = User::factory()->create();
        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'device-to-trust-01',
            'is_trusted' => false,
        ]);

        $trustResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'device-to-trust-01')
            ->postJson("/api/user/devices/{$device->id}/trust");

        $trustResponse->assertStatus(200);
        $this->assertTrue($device->fresh()->is_trusted);

        $revokeResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'device-to-trust-01')
            ->deleteJson("/api/user/devices/{$device->id}");

        $revokeResponse->assertStatus(200);
        $this->assertDatabaseMissing('devices', ['id' => $device->id]);
    }

    public function test_user_can_access_account_devices_and_sessions(): void
    {
        $user = User::factory()->create();
        $device = Device::create([
            'user_id' => $user->id,
            'device_identifier' => 'device-account-01',
            'device_name' => 'Chrome on Windows 11',
            'operating_system' => 'Windows 11',
            'browser' => 'Chrome',
            'ip_address' => '127.0.0.1',
            'is_trusted' => true,
        ]);

        // Test account/devices
        $devicesResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'device-account-01')
            ->getJson('/api/account/devices');

        $devicesResponse->assertStatus(200)
            ->assertJsonPath('data.0.name', 'Chrome on Windows 11')
            ->assertJsonPath('data.0.os', 'Windows 11')
            ->assertJsonPath('data.0.isCurrent', true)
            ->assertJsonPath('data.0.isTrusted', true);

        // Test account/sessions
        $sessionsResponse = $this->actingAs($user, 'web')
            ->withHeader('X-Device-Id', 'device-account-01')
            ->getJson('/api/account/sessions');

        $sessionsResponse->assertStatus(200)
            ->assertJsonStructure(['status', 'data']);
    }

    public function test_admin_can_manage_devices_and_sessions(): void
    {
        $admin = User::factory()->create(['type' => User::TYPE_ADMIN]);
        $device = Device::create([
            'user_id' => $admin->id,
            'device_identifier' => 'device-admin-01',
            'device_name' => 'Safari on macOS',
            'operating_system' => 'macOS',
            'browser' => 'Safari',
            'is_trusted' => true,
        ]);

        $adminDevicesResponse = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', 'device-admin-01')
            ->getJson('/api/admin/devices');

        $adminDevicesResponse->assertStatus(200)
            ->assertJsonPath('data.0.status', 'Trusted');

        $adminSessionsResponse = $this->actingAs($admin, 'web')
            ->withHeader('X-Device-Id', 'device-admin-01')
            ->getJson('/api/admin/sessions');

        $adminSessionsResponse->assertStatus(200)
            ->assertJsonStructure(['status', 'data']);
    }
}
