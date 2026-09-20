<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use App\Models\Device;
use App\Models\User;
use App\Services\AuditLogService;
use App\Services\DeviceService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class DeviceController extends Controller
{
    public function __construct(
        protected DeviceService $deviceService,
        protected AuditLogService $auditLogService
    ) {}

    /**
     * List devices registered to the authenticated user.
     */
    public function index(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $currentDeviceId = $request->header('X-Device-Id');

        $devices = $user->devices()
            ->withCount('sightings')
            ->latest('last_seen_at')
            ->get();

        $data = $devices->map(function (Device $device) use ($currentDeviceId) {
            $isCurrent = ($device->device_identifier === $currentDeviceId) || ((string) $device->id === (string) $currentDeviceId);

            return [
                'id' => $device->id,
                'deviceId' => $device->device_identifier,
                'device_identifier' => $device->device_identifier,
                'name' => $device->device_name,
                'device_name' => $device->device_name,
                'os' => $device->operating_system,
                'operating_system' => $device->operating_system,
                'browser' => $device->browser,
                'ipAddress' => $device->ip_address,
                'ip_address' => $device->ip_address,
                'isTrusted' => (bool) $device->is_trusted,
                'is_trusted' => (bool) $device->is_trusted,
                'isBlocked' => (bool) $device->is_blocked,
                'is_blocked' => (bool) $device->is_blocked,
                'isCurrent' => $isCurrent,
                'lastSeenAt' => $device->last_seen_at?->toIso8601String(),
                'last_seen_at' => $device->last_seen_at?->toIso8601String(),
                'createdAt' => $device->created_at?->toIso8601String(),
                'created_at' => $device->created_at?->toIso8601String(),
                'sightings_count' => $device->sightings_count,
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => $data,
        ]);
    }

    /**
     * Mark device as trusted by user.
     */
    public function trustDevice(Request $request, Device $device): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        if ($device->user_id !== $user->id && ! $user->isAdmin()) {
            return response()->json(['status' => 'error', 'message' => 'Unauthorized.'], 403);
        }

        $this->deviceService->setTrustStatus($device->id, true);

        $this->auditLogService->recordFromRequest(
            $request,
            'DEVICE',
            'DEVICE_TRUSTED',
            "Device {$device->device_identifier} marked as trusted",
            ['device_id' => $device->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Device marked as trusted.',
            'data' => $device->fresh(),
        ]);
    }

    /**
     * Revoke or remove a device.
     */
    public function revokeDevice(Request $request, Device $device): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        if ($device->user_id !== $user->id && ! $user->isAdmin()) {
            return response()->json(['status' => 'error', 'message' => 'Unauthorized.'], 403);
        }

        $identifier = $device->device_identifier;
        $device->delete();

        $this->auditLogService->recordFromRequest(
            $request,
            'DEVICE',
            'DEVICE_REVOKED',
            "Device {$identifier} revoked by user",
            ['device_identifier' => $identifier]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Device access revoked successfully.',
        ]);
    }
}
