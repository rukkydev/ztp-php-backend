<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Device;
use App\Services\AuditLogService;
use App\Services\DeviceService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AdminDeviceController extends Controller
{
    public function __construct(
        protected DeviceService $deviceService,
        protected AuditLogService $auditLogService
    ) {}

    /**
     * List all devices registered across the organization.
     */
    public function index(): JsonResponse
    {
        $devices = Device::with('user')->latest('last_seen_at')->get();

        $data = $devices->map(function (Device $device) {
            $status = $device->is_blocked ? 'Blocked' : ($device->is_trusted ? 'Trusted' : 'Pending');

            return [
                'id' => $device->id,
                'deviceId' => $device->device_identifier,
                'userId' => $device->user_id,
                'owner' => $device->user?->username ?? 'Unknown',
                'name' => $device->device_name,
                'userAgent' => $device->device_name,
                'os' => $device->operating_system,
                'browser' => $device->browser,
                'ipAddress' => $device->ip_address,
                'status' => $status,
                'isTrusted' => (bool) $device->is_trusted,
                'isBlocked' => (bool) $device->is_blocked,
                'lastSeenAt' => $device->last_seen_at?->toIso8601String(),
                'createdAt' => $device->created_at?->toIso8601String(),
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => $data,
        ]);
    }

    /**
     * Update device trust/block status.
     */
    public function updateStatus(Request $request, Device $device): JsonResponse
    {
        $status = $request->input('status');

        if ($status === 'Blocked') {
            $this->deviceService->isolateDevice($device->id, 'Manually blocked by administrator');
        } elseif ($status === 'Trusted') {
            $device->update(['is_trusted' => true, 'is_blocked' => false]);
            $this->auditLogService->recordFromRequest(
                $request,
                'DEVICE',
                'DEVICE_TRUSTED',
                "Device {$device->device_identifier} marked as trusted by administrator",
                ['device_id' => $device->id]
            );
        }

        return response()->json([
            'status' => 'success',
            'message' => "Device status updated to {$status}.",
            'data' => $device->fresh(),
        ]);
    }

    /**
     * Bulk block devices.
     */
    public function bulkBlock(Request $request): JsonResponse
    {
        $request->validate([
            'ids' => ['required', 'array'],
        ]);

        $ids = $request->input('ids', []);
        foreach ($ids as $id) {
            $this->deviceService->isolateDevice((int) $id, 'Bulk blocked by administrator');
        }

        return response()->json([
            'status' => 'success',
            'message' => count($ids).' devices blocked.',
        ]);
    }
}
