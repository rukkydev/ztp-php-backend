<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;

class AdminDashboardController extends Controller
{
    /**
     * Provide statistics and recent activity for the admin dashboard.
     */
    public function index(): JsonResponse
    {
        $totalUsers = User::count();
        $activeUsers = User::where('is_active', true)->where('account_locked', false)->count();
        $suspendedUsers = User::where('is_active', false)->count();
        $lockedAccounts = User::where('account_locked', true)->count();

        $recentLogs = AuditLog::latest('created_at')->take(10)->get();

        $recentActivity = $recentLogs->map(function (AuditLog $log) {
            return [
                'id' => $log->id,
                'eventType' => $log->action,
                'actorUsername' => $log->actor_username ?? 'System',
                'description' => $log->details,
                'createdAt' => $log->created_at?->toIso8601String() ?? now()->toIso8601String(),
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => [
                'stats' => [
                    'totalUsers' => $totalUsers,
                    'activeUsers' => $activeUsers,
                    'suspendedUsers' => $suspendedUsers,
                    'lockedAccounts' => $lockedAccounts,
                ],
                'resources' => null,
                'detectionTimeline' => null,
                'recentActivity' => $recentActivity,
            ],
        ]);
    }
}
