<?php

namespace App\Http\Controllers\Analyst;

use App\Http\Controllers\Controller;
use App\Http\Requests\Analyst\ManualMitigateRequest;
use App\Models\Device;
use App\Models\ResponseAction;
use App\Models\User;
use App\Services\AuditLogService;
use App\Services\DeviceService;
use App\Services\ThreatPreventionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

class ThreatResponseController extends Controller
{
    public function __construct(
        protected ThreatPreventionService $threatPreventionService,
        protected DeviceService $deviceService,
        protected AuditLogService $auditLogService
    ) {}

    /**
     * List all automated and manual response actions.
     */
    public function actions(Request $request): JsonResponse
    {
        Gate::authorize('viewAny', ResponseAction::class);

        $query = ResponseAction::query()->with('riskLog');

        if ($request->filled('target_type')) {
            $query->where('target_type', $request->input('target_type'));
        }

        if ($request->filled('action_taken')) {
            $query->where('action_taken', $request->input('action_taken'));
        }

        if ($request->filled('status')) {
            $query->where('status', $request->input('status'));
        }

        $actions = $query->latest('executed_at')->paginate($request->integer('per_page', 25));

        return response()->json([
            'status' => 'success',
            'data' => $actions,
        ]);
    }

    /**
     * Trigger manual mitigation on a target (User, Device, Session, IP).
     */
    public function manualMitigate(ManualMitigateRequest $request): JsonResponse
    {
        Gate::authorize('mitigate', ResponseAction::class);

        $validated = $request->validated();
        $targetType = $validated['target_type'];
        $identifier = $validated['target_identifier'];
        $action = $validated['action'];

        $responseAction = null;

        if ($targetType === ResponseAction::TARGET_DEVICE) {
            $device = Device::where('device_identifier', $identifier)->first();
            if ($device) {
                $responseAction = $this->threatPreventionService->blockDeviceMitigation($device);
            } else {
                $this->deviceService->blockDevice($identifier);
                $responseAction = ResponseAction::create([
                    'correlation_id' => (string) Str::uuid(),
                    'target_type' => ResponseAction::TARGET_DEVICE,
                    'target_identifier' => $identifier,
                    'action_taken' => ResponseAction::ACTION_BLOCK_DEVICE,
                    'status' => ResponseAction::STATUS_EXECUTED,
                    'executed_at' => now(),
                ]);
            }
        } elseif ($targetType === ResponseAction::TARGET_USER) {
            $user = User::where('id', $identifier)->orWhere('username', $identifier)->firstOrFail();
            if ($action === ResponseAction::ACTION_LOCK_ACCOUNT) {
                $responseAction = $this->threatPreventionService->lockAccountMitigation($user);
            } elseif ($action === ResponseAction::ACTION_KILL_SESSIONS) {
                $responseAction = $this->threatPreventionService->killSessionsMitigation($user);
            } elseif ($action === ResponseAction::ACTION_FORCE_MFA) {
                $responseAction = $this->threatPreventionService->forceMfaMitigation($user);
            }
        }

        $this->auditLogService->recordFromRequest(
            $request,
            'THREAT_RESPONSE',
            'MANUAL_MITIGATION_EXECUTED',
            "Manual mitigation {$action} executed against {$targetType}: {$identifier}",
            ['target_type' => $targetType, 'target_identifier' => $identifier, 'action' => $action]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Mitigation action executed successfully.',
            'data' => $responseAction,
        ]);
    }

    /**
     * Revert or override a mitigation action.
     */
    public function revertAction(Request $request, ResponseAction $responseAction): JsonResponse
    {
        Gate::authorize('revert', $responseAction);

        $this->threatPreventionService->revertAction($responseAction, $request->user());

        return response()->json([
            'status' => 'success',
            'message' => 'Response action reverted successfully.',
            'data' => $responseAction->fresh(),
        ]);
    }

    /**
     * Unblock a device directly.
     */
    public function unblockDevice(Request $request, Device $device): JsonResponse
    {
        $this->deviceService->unblockDevice($device->id);

        $this->auditLogService->recordFromRequest(
            $request,
            'DEVICE',
            'DEVICE_UNBLOCKED',
            "Device {$device->device_identifier} ({$device->device_name}) unblocked by analyst",
            ['device_id' => $device->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Device unblocked successfully.',
            'data' => $device->fresh(),
        ]);
    }
}
