<?php

namespace App\Http\Controllers\Security;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class AuditLogController extends Controller
{
    /**
     * List audit trail records with filters.
     */
    public function index(Request $request): JsonResponse
    {
        Gate::authorize('viewAny', AuditLog::class);

        $query = AuditLog::query()->with('actor:id,username,name,type');

        if ($request->filled('event_category')) {
            $query->where('event_category', $request->input('event_category'));
        }

        if ($request->filled('action')) {
            $query->where('action', $request->input('action'));
        }

        if ($request->filled('actor_id')) {
            $query->where('actor_id', $request->integer('actor_id'));
        }

        if ($request->filled('search')) {
            $search = '%'.$request->input('search').'%';
            $query->where(function ($q) use ($search) {
                $q->where('actor_username', 'like', $search)
                    ->orWhere('description', 'like', $search)
                    ->orWhere('ip_address', 'like', $search);
            });
        }

        $logs = $query->latest('id')->paginate($request->integer('per_page', 50));

        return response()->json([
            'status' => 'success',
            'data' => $logs,
        ]);
    }

    /**
     * Export audit trail.
     */
    public function export(Request $request): JsonResponse
    {
        Gate::authorize('export', AuditLog::class);

        $logs = AuditLog::with('actor:id,username,email,type')
            ->latest('id')
            ->take(1000)
            ->get();

        return response()->json([
            'status' => 'success',
            'data' => $logs,
            'count' => $logs->count(),
            'exported_at' => now()->toIso8601String(),
        ]);
    }

    /**
     * Display a specific audit log record.
     */
    public function show(AuditLog $auditLog): JsonResponse
    {
        Gate::authorize('view', $auditLog);

        $auditLog->load('actor:id,username,name,type');

        return response()->json([
            'status' => 'success',
            'data' => $auditLog,
        ]);
    }
}
