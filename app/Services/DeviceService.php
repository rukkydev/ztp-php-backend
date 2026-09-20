<?php

namespace App\Services;

use App\Models\Device;
use App\Models\DeviceSighting;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;

class DeviceService
{
    /**
     * Resolve or register a device for the given user and request.
     */
    public function resolveDevice(User $user, Request $request): Device
    {
        $deviceIdentifier = $request->header('X-Device-Id') ?? $request->input('device_id') ?? 'unknown-device';
        $ip = $request->ip();
        $userAgent = $request->userAgent() ?? 'Unknown Agent';

        $parsed = $this->parseUserAgent($userAgent);

        $device = Device::firstOrCreate(
            [
                'user_id' => $user->id,
                'device_identifier' => $deviceIdentifier,
            ],
            [
                'device_name' => $parsed['browser'].' on '.$parsed['os'],
                'device_type' => $parsed['device_type'],
                'browser' => $parsed['browser'],
                'operating_system' => $parsed['os'],
                'ip_address' => $ip,
                'is_trusted' => false,
                'is_blocked' => false,
                'last_seen_at' => Carbon::now(),
            ]
        );

        // Update last seen and IP
        $device->update([
            'ip_address' => $ip,
            'browser' => $parsed['browser'],
            'operating_system' => $parsed['os'],
            'last_seen_at' => Carbon::now(),
        ]);

        // Record sighting
        $this->recordSighting($device, $user, $request);

        return $device;
    }

    /**
     * Record a device sighting.
     */
    public function recordSighting(Device $device, User $user, Request $request): DeviceSighting
    {
        return DeviceSighting::create([
            'device_id' => $device->id,
            'user_id' => $user->id,
            'ip_address' => $request->ip() ?? '127.0.0.1',
            'user_agent' => $request->userAgent(),
            'city' => $request->header('CF-IPCity') ?? $request->header('X-City') ?? 'Local / Unknown',
            'country' => $request->header('CF-IPCountry') ?? $request->header('X-Country') ?? 'US',
            'sighted_at' => Carbon::now(),
        ]);
    }

    /**
     * Check if a device identifier is blocked.
     */
    public function isDeviceBlocked(string $deviceIdentifier): bool
    {
        return Device::where('device_identifier', $deviceIdentifier)
            ->where('is_blocked', true)
            ->exists();
    }

    /**
     * Block a device identifier across users or for a specific user.
     */
    public function blockDevice(string $deviceIdentifier): int
    {
        return Device::where('device_identifier', $deviceIdentifier)
            ->update(['is_blocked' => true]);
    }

    /**
     * Unblock a device.
     */
    public function unblockDevice(int $deviceId): bool
    {
        $device = Device::find($deviceId);
        if (! $device) {
            return false;
        }

        return $device->update(['is_blocked' => false]);
    }

    /**
     * Set device trust status.
     */
    public function setTrustStatus(int $deviceId, bool $isTrusted): bool
    {
        $device = Device::find($deviceId);
        if (! $device) {
            return false;
        }

        return $device->update(['is_trusted' => $isTrusted]);
    }

    /**
     * Basic user agent parser for OS, browser, and device type.
     *
     * @return array{browser: string, os: string, device_type: string}
     */
    public function parseUserAgent(?string $userAgent): array
    {
        if (! $userAgent) {
            return ['browser' => 'Unknown Browser', 'os' => 'Unknown OS', 'device_type' => 'desktop'];
        }

        // OS Detection
        $os = 'Unknown OS';
        if (preg_match('/windows nt 10/i', $userAgent)) {
            $os = 'Windows 10/11';
        } elseif (preg_match('/windows nt 6/i', $userAgent)) {
            $os = 'Windows 7/8';
        } elseif (preg_match('/macintosh|mac os x/i', $userAgent)) {
            $os = 'macOS';
        } elseif (preg_match('/android/i', $userAgent)) {
            $os = 'Android';
        } elseif (preg_match('/iphone|ipad|ipod/i', $userAgent)) {
            $os = 'iOS';
        } elseif (preg_match('/linux/i', $userAgent)) {
            $os = 'Linux';
        }

        // Browser Detection
        $browser = 'Unknown Browser';
        if (preg_match('/edg/i', $userAgent)) {
            $browser = 'Edge';
        } elseif (preg_match('/chrome|crios/i', $userAgent)) {
            $browser = 'Chrome';
        } elseif (preg_match('/firefox|fxios/i', $userAgent)) {
            $browser = 'Firefox';
        } elseif (preg_match('/safari/i', $userAgent) && ! preg_match('/chrome/i', $userAgent)) {
            $browser = 'Safari';
        } elseif (preg_match('/opera|opr/i', $userAgent)) {
            $browser = 'Opera';
        }

        // Device Type
        $deviceType = 'desktop';
        if (preg_match('/mobile/i', $userAgent)) {
            $deviceType = 'mobile';
        } elseif (preg_match('/tablet|ipad/i', $userAgent)) {
            $deviceType = 'tablet';
        }

        return [
            'browser' => $browser,
            'os' => $os,
            'device_type' => $deviceType,
        ];
    }
}
