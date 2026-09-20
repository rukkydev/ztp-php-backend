<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SessionController extends Controller
{
    /**
     * List active sessions for the current authenticated user.
     */
    public function index(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $currentSessionId = $request->session()->getId();

        $sessions = DB::table('sessions')
            ->where('user_id', $user->id)
            ->orderByDesc('last_activity')
            ->get();

        $data = $sessions->map(function ($session) use ($currentSessionId, $user) {
            $isCurrent = ($session->id === $currentSessionId);
            $lastActiveDate = Carbon::createFromTimestamp($session->last_activity);

            return [
                'id' => $session->id,
                'sessionId' => $session->id,
                'isCurrent' => $isCurrent,
                'current' => $isCurrent,
                'active' => true,
                'username' => $user->username,
                'userId' => $user->id,
                'ipAddress' => $session->ip_address,
                'ip' => $session->ip_address,
                'userAgent' => $session->user_agent,
                'device' => $session->user_agent,
                'location' => 'Local Network',
                'startedAt' => $lastActiveDate->toIso8601String(),
                'createdAt' => $lastActiveDate->toIso8601String(),
                'lastRequest' => $lastActiveDate->toIso8601String(),
                'lastActive' => $lastActiveDate->toIso8601String(),
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => $data,
        ]);
    }

    /**
     * Terminate a specific user session.
     */
    public function destroy(Request $request, string $sessionId): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        DB::table('sessions')
            ->where('id', $sessionId)
            ->where('user_id', $user->id)
            ->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'Session signed out successfully.',
        ]);
    }

    /**
     * Terminate all other sessions for the user except the current one.
     */
    public function destroyOthers(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $currentSessionId = $request->session()->getId();

        DB::table('sessions')
            ->where('user_id', $user->id)
            ->where('id', '!=', $currentSessionId)
            ->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'All other sessions have been signed out.',
        ]);
    }
}
