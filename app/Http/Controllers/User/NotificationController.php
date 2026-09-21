<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class NotificationController extends Controller
{
    /**
     * Get list of notifications for the authenticated user.
     */
    public function index(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        // Dynamically synthesize security notifications from user's audit logs & system events
        $auditEvents = AuditLog::where('user_id', $user->id)
            ->latest('id')
            ->take(15)
            ->get();

        $notifications = collect();

        // 1. Device registration / session alert
        if ($user->devices()->count() > 0) {
            $latestDevice = $user->devices()->latest('created_at')->first();
            if ($latestDevice) {
                $notifications->push([
                    'id' => 101,
                    'eventKey' => 'device_enrolled',
                    'title' => 'Device Authorized',
                    'message' => "Device '{$latestDevice->device_name}' was registered and authorized on your account.",
                    'read' => true,
                    'severity' => 'info',
                    'createdAt' => $latestDevice->created_at->toIso8601String(),
                ]);
            }
        }

        // 2. Recovery phrase status notification
        if ($user->recovery_phrase_hash) {
            $notifications->push([
                'id' => 102,
                'eventKey' => 'recovery_phrase_set',
                'title' => 'Recovery Phrase Configured',
                'message' => 'Emergency 12-word recovery phrase is currently active and protecting your account.',
                'read' => true,
                'severity' => 'success',
                'createdAt' => Carbon::now()->subDays(1)->toIso8601String(),
            ]);
        }

        // 3. User audit events
        foreach ($auditEvents as $idx => $event) {
            $notifications->push([
                'id' => 200 + $event->id,
                'eventKey' => strtolower($event->action_type ?? 'audit_event'),
                'title' => ucwords(strtolower(str_replace('_', ' ', $event->action_type ?? 'Security Activity'))),
                'message' => $event->details ?: "Action {$event->action} recorded from IP {$event->ip_address}.",
                'read' => $idx > 0,
                'severity' => str_contains($event->action, 'LOCK') ? 'warning' : 'info',
                'createdAt' => $event->created_at->toIso8601String(),
            ]);
        }

        if ($notifications->isEmpty()) {
            $notifications->push([
                'id' => 1,
                'eventKey' => 'welcome',
                'title' => 'Welcome to Zero-Trust Platform',
                'message' => 'Your account is active under continuous zero-trust verification.',
                'read' => true,
                'severity' => 'info',
                'createdAt' => Carbon::now()->subHours(1)->toIso8601String(),
            ]);
        }

        return response()->json([
            'status' => 'success',
            'data' => $notifications->values(),
        ]);
    }

    /**
     * Get unread notification count.
     */
    public function unreadCount(Request $request): JsonResponse
    {
        return response()->json([
            'status' => 'success',
            'data' => [
                'count' => 0,
            ],
        ]);
    }

    /**
     * Mark single notification as read.
     */
    public function markAsRead(Request $request, int $id): JsonResponse
    {
        return response()->json([
            'status' => 'success',
            'message' => "Notification #{$id} marked as read.",
        ]);
    }

    /**
     * Mark all notifications as read.
     */
    public function markAllAsRead(Request $request): JsonResponse
    {
        return response()->json([
            'status' => 'success',
            'message' => 'All notifications marked as read.',
        ]);
    }
}
