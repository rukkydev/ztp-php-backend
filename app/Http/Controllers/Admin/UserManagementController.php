<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\CreateUserRequest;
use App\Http\Requests\Admin\UpdateUserRequest;
use App\Models\User;
use App\Services\AuditLogService;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class UserManagementController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService
    ) {}

    /**
     * List all users with filtering, sorting, and pagination.
     */
    public function index(Request $request): JsonResponse
    {
        Gate::authorize('viewAny', User::class);

        $query = User::query()->withCount(['devices', 'accessRequests']);

        if ($request->filled('type')) {
            $query->where('type', $request->input('type'));
        }

        if ($request->filled('status')) {
            if ($request->input('status') === 'active') {
                $query->where('is_active', true)->where('account_locked', false);
            } elseif ($request->input('status') === 'locked') {
                $query->where('account_locked', true);
            } elseif ($request->input('status') === 'inactive') {
                $query->where('is_active', false);
            }
        }

        if ($request->filled('search')) {
            $search = '%'.$request->input('search').'%';
            $query->where(function ($q) use ($search) {
                $q->where('username', 'like', $search)
                    ->orWhere('name', 'like', $search)
                    ->orWhere('email', 'like', $search)
                    ->orWhere('department', 'like', $search);
            });
        }

        $users = $query->latest()->paginate($request->integer('per_page', 20));

        return response()->json([
            'status' => 'success',
            'data' => $users,
        ]);
    }

    /**
     * Store a newly created user (Admin provisioned).
     */
    public function store(CreateUserRequest $request): JsonResponse
    {
        Gate::authorize('create', User::class);

        $user = User::create($request->validated());

        $this->auditLogService->recordFromRequest(
            $request,
            'USER_MANAGEMENT',
            'USER_CREATED',
            "User {$user->username} ({$user->type}) created by administrator",
            ['target_user_id' => $user->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'User created successfully.',
            'data' => $user,
        ], 201);
    }

    /**
     * Display specified user with devices and recent sightings.
     */
    public function show(User $user): JsonResponse
    {
        Gate::authorize('view', $user);

        $user->load([
            'devices' => fn ($q) => $q->latest('last_seen_at')->take(10),
            'sightings' => fn ($q) => $q->latest('sighted_at')->take(10),
            'riskLogs' => fn ($q) => $q->latest('evaluated_at')->take(10),
        ]);

        return response()->json([
            'status' => 'success',
            'data' => $user,
        ]);
    }

    /**
     * Update user details.
     */
    public function update(UpdateUserRequest $request, User $user): JsonResponse
    {
        Gate::authorize('update', $user);

        $user->update($request->validated());

        $this->auditLogService->recordFromRequest(
            $request,
            'USER_MANAGEMENT',
            'USER_UPDATED',
            "User {$user->username} profile updated",
            ['target_user_id' => $user->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'User updated successfully.',
            'data' => $user->fresh(),
        ]);
    }

    /**
     * Remove or deactivate a user.
     */
    public function destroy(Request $request, User $user): JsonResponse
    {
        Gate::authorize('delete', $user);

        $username = $user->username;
        $user->delete();

        $this->auditLogService->recordFromRequest(
            $request,
            'USER_MANAGEMENT',
            'USER_DELETED',
            "User {$username} permanently deleted",
            ['target_user_id' => $user->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'User deleted successfully.',
        ]);
    }

    /**
     * Lock a user account manually.
     */
    public function lockUser(Request $request, User $user): JsonResponse
    {
        Gate::authorize('manageLock', $user);

        $user->update([
            'account_locked' => true,
            'locked_until' => Carbon::now()->addHours(24),
        ]);

        $this->auditLogService->recordFromRequest(
            $request,
            'USER_MANAGEMENT',
            'USER_MANUALLY_LOCKED',
            "User {$user->username} manually locked by administrator",
            ['target_user_id' => $user->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'User account has been locked.',
            'data' => $user->fresh(),
        ]);
    }

    /**
     * Unlock a user account.
     */
    public function unlockUser(Request $request, User $user): JsonResponse
    {
        Gate::authorize('manageLock', $user);

        $user->update([
            'account_locked' => false,
            'locked_until' => null,
            'failed_login_attempts' => 0,
        ]);

        $this->auditLogService->recordFromRequest(
            $request,
            'USER_MANAGEMENT',
            'USER_UNLOCKED',
            "User {$user->username} unlocked by administrator",
            ['target_user_id' => $user->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'User account unlocked successfully.',
            'data' => $user->fresh(),
        ]);
    }
}
