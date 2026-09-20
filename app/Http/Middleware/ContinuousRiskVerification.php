<?php

namespace App\Http\Middleware;

use App\Models\Device;
use App\Models\User;
use App\Services\AuditLogService;
use App\Services\DeviceService;
use App\Services\NetworkMonitoringService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class ContinuousRiskVerification
{
    public function __construct(
        protected DeviceService $deviceService,
        protected NetworkMonitoringService $networkMonitoringService,
        protected AuditLogService $auditLogService
    ) {}

    /**
     * Handle continuous zero-trust verification and traffic logging.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $startTime = microtime(true);
        $deviceIdentifier = $request->header('X-Device-Id');

        // Check if device is blocked
        if ($deviceIdentifier && $this->deviceService->isDeviceBlocked($deviceIdentifier)) {
            if (Auth::guard('web')->check()) {
                Auth::guard('web')->logout();
                $request->session()->invalidate();
            }

            return response()->json([
                'status' => 'error',
                'error_code' => 'DEVICE_BLOCKED',
                'message' => 'Access Denied: This device has been isolated and blocked by Zero-Trust security policies.',
            ], Response::HTTP_FORBIDDEN);
        }

        // Check user lockout / active status if authenticated
        /** @var User|null $user */
        $user = $request->user();
        if ($user) {
            if ($user->isLocked()) {
                Auth::guard('web')->logout();
                $request->session()->invalidate();

                return response()->json([
                    'status' => 'error',
                    'error_code' => 'ACCOUNT_LOCKED',
                    'message' => 'Access Denied: Your account has been locked. Contact security administration.',
                ], Response::HTTP_FORBIDDEN);
            }

            if (! $user->is_active) {
                Auth::guard('web')->logout();
                $request->session()->invalidate();

                return response()->json([
                    'status' => 'error',
                    'error_code' => 'ACCOUNT_INACTIVE',
                    'message' => 'Access Denied: Your account has been deactivated.',
                ], Response::HTTP_FORBIDDEN);
            }
        }

        $response = $next($request);

        $durationMs = (int) round((microtime(true) - $startTime) * 1000);

        // Record network event
        $device = null;
        if ($deviceIdentifier && $user) {
            $device = Device::where('user_id', $user->id)
                ->where('device_identifier', $deviceIdentifier)
                ->first();
        }

        $this->networkMonitoringService->recordEvent(
            $request,
            $user,
            $device,
            $this->determineEventType($request),
            $response->getStatusCode(),
            $durationMs
        );

        return $response;
    }

    protected function determineEventType(Request $request): string
    {
        $path = $request->path();

        if (str_contains($path, 'login') || str_contains($path, 'auth')) {
            return 'LOGIN_ATTEMPT';
        }
        if (str_contains($path, 'admin/policies')) {
            return 'POLICY_MUTATION';
        }
        if (str_contains($path, 'analyst/mitigate') || str_contains($path, 'threat-response')) {
            return 'THREAT_RESPONSE_ACTION';
        }

        return 'API_ACCESS';
    }
}
