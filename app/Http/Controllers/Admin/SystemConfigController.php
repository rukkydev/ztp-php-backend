<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;

class SystemConfigController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService
    ) {}

    /**
     * Get system configuration status.
     */
    public function index(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        if (! $user->isAdmin()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized.',
            ], 403);
        }

        return response()->json([
            'status' => 'success',
            'data' => [
                'app_env' => Config::get('app.env'),
                'app_url' => Config::get('app.url'),
                'risk_engine' => [
                    'base_url' => Config::get('services.risk_engine.base_url', 'http://127.0.0.1:8081'),
                    'timeout_ms' => Config::get('services.risk_engine.timeout_ms', 400),
                ],
                'resend' => [
                    'configured' => ! empty(Config::get('services.resend.key')),
                    'from' => Config::get('services.resend.from', 'onboarding@resend.dev'),
                ],
                'session' => [
                    'driver' => Config::get('session.driver'),
                    'lifetime' => Config::get('session.lifetime'),
                    'same_site' => Config::get('session.same_site'),
                    'secure' => Config::get('session.secure'),
                ],
            ],
        ]);
    }
}
