<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class AdminSessionController extends Controller
{
    /**
     * List all active sessions across the platform.
     */
    public function index(Request $request): JsonResponse
    {
        $currentSessionId = $request->session()->getId();

        $sessions = DB::table('sessions')
            ->whereNotNull('user_id')
            ->orderByDesc('last_activity')
            ->get();

        $userIds = $sessions->pluck('user_id')->filter()->unique();
        $users = User::whereIn('id', $userIds)->get()->keyBy('id');

        $data = $sessions->map(function ($session) use ($currentSessionId, $users) {
            $user = $users->get($session->user_id);
            $lastActiveDate = Carbon::createFromTimestamp($session->last_activity);
            $isCurrent = ($session->id === $currentSessionId);

            return [
                'id' => $session->id,
                'sessionId' => $session->id,
                'userId' => $session->user_id,
                'username' => $user?->username ?? 'Unknown',
                'email' => $user?->email,
                'ipAddress' => $session->ip_address,
                'userAgent' => $session->user_agent,
                'lastRequest' => $lastActiveDate->toIso8601String(),
                'lastActive' => $lastActiveDate->toIso8601String(),
                'createdAt' => $lastActiveDate->toIso8601String(),
                'isCurrent' => $isCurrent,
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => $data,
        ]);
    }

    /**
     * Invalidate any single user session.
     */
    public function destroy(Request $request, string $sessionId): JsonResponse
    {
        DB::table('sessions')->where('id', $sessionId)->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'Session terminated successfully.',
        ]);
    }

    /**
     * Invalidate multiple user sessions.
     */
    public function bulkDestroy(Request $request): JsonResponse
    {
        $request->validate([
            'ids' => ['required', 'array'],
            'ids.*' => ['required', 'string'],
        ]);

        $ids = $request->input('ids', []);
        DB::table('sessions')->whereIn('id', $ids)->delete();

        return response()->json([
            'status' => 'success',
            'message' => count($ids).' sessions terminated successfully.',
        ]);
    }
}
