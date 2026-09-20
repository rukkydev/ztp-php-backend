<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\StorePolicyRequest;
use App\Http\Requests\Admin\UpdatePolicyRequest;
use App\Models\SecurityPolicy;
use App\Services\AuditLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class PolicyController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService
    ) {}

    /**
     * List all zero-trust security policies.
     */
    public function index(Request $request): JsonResponse
    {
        Gate::authorize('viewAny', SecurityPolicy::class);

        $query = SecurityPolicy::query()->with('creator:id,username,name');

        if ($request->has('is_enabled')) {
            $query->where('is_enabled', $request->boolean('is_enabled'));
        }

        $policies = $query->latest()->get();

        return response()->json([
            'status' => 'success',
            'data' => $policies,
        ]);
    }

    /**
     * Create a new security policy.
     */
    public function store(StorePolicyRequest $request): JsonResponse
    {
        Gate::authorize('create', SecurityPolicy::class);

        $data = $request->validated();
        $data['created_by'] = $request->user()?->id;

        $policy = SecurityPolicy::create($data);

        $this->auditLogService->recordFromRequest(
            $request,
            'POLICY',
            'POLICY_CREATED',
            "Security policy '{$policy->policy_name}' created",
            ['policy_id' => $policy->id, 'rule_type' => $policy->rule_type]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Security policy created successfully.',
            'data' => $policy->load('creator:id,username,name'),
        ], 201);
    }

    /**
     * Display a specific policy.
     */
    public function show(SecurityPolicy $policy): JsonResponse
    {
        Gate::authorize('view', $policy);

        return response()->json([
            'status' => 'success',
            'data' => $policy->load('creator:id,username,name'),
        ]);
    }

    /**
     * Update a security policy.
     */
    public function update(UpdatePolicyRequest $request, SecurityPolicy $policy): JsonResponse
    {
        Gate::authorize('update', $policy);

        $policy->update($request->validated());

        $this->auditLogService->recordFromRequest(
            $request,
            'POLICY',
            'POLICY_UPDATED',
            "Security policy '{$policy->policy_name}' updated",
            ['policy_id' => $policy->id]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Security policy updated successfully.',
            'data' => $policy->fresh()->load('creator:id,username,name'),
        ]);
    }

    /**
     * Toggle policy enabled status.
     */
    public function toggle(Request $request, SecurityPolicy $policy): JsonResponse
    {
        Gate::authorize('toggle', $policy);

        $policy->update(['is_enabled' => ! $policy->is_enabled]);

        $status = $policy->is_enabled ? 'enabled' : 'disabled';

        $this->auditLogService->recordFromRequest(
            $request,
            'POLICY',
            'POLICY_TOGGLED',
            "Security policy '{$policy->policy_name}' was {$status}",
            ['policy_id' => $policy->id, 'is_enabled' => $policy->is_enabled]
        );

        return response()->json([
            'status' => 'success',
            'message' => "Policy '{$policy->policy_name}' {$status}.",
            'data' => $policy->fresh(),
        ]);
    }

    /**
     * Delete a policy.
     */
    public function destroy(Request $request, SecurityPolicy $policy): JsonResponse
    {
        Gate::authorize('delete', $policy);

        $name = $policy->policy_name;
        $policy->delete();

        $this->auditLogService->recordFromRequest(
            $request,
            'POLICY',
            'POLICY_DELETED',
            "Security policy '{$name}' permanently deleted",
            ['policy_name' => $name]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Policy deleted successfully.',
        ]);
    }
}
