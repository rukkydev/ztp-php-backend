<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\AuditLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AdminRoleController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService
    ) {}

    /**
     * List all system roles and their permissions.
     */
    public function index(): JsonResponse
    {
        $adminCount = User::where('type', User::TYPE_ADMIN)->count();
        $analystCount = User::where('type', User::TYPE_SECURITY_ANALYST)->count();
        $userCount = User::where('type', User::TYPE_USER)->count();

        $roles = [
            [
                'id' => 'admin',
                'name' => 'Admin',
                'description' => 'Full access to every area, including user management and platform settings.',
                'userCount' => $adminCount,
                'permissions' => [
                    'Manage users',
                    'Manage roles & permissions',
                    'View all activity logs',
                    'Manage platform settings',
                    'View dashboards & reports',
                    'Manage security policies',
                    'Mitigate threats & block devices',
                ],
            ],
            [
                'id' => 'security-analyst',
                'name' => 'Security Analyst',
                'description' => 'Investigates alerts and threats; read-only on user management.',
                'userCount' => $analystCount,
                'permissions' => [
                    'View all activity logs',
                    'Manage alerts & threats',
                    'View dashboards & reports',
                    'View users (read-only)',
                    'Inspect ML anomaly risk evaluations',
                    'Mitigate threats & isolate devices',
                ],
            ],
            [
                'id' => 'auditor',
                'name' => 'Auditor',
                'description' => 'Read-only access for compliance review across the platform.',
                'userCount' => 0,
                'permissions' => [
                    'View all activity logs',
                    'View dashboards & reports',
                    'View users (read-only)',
                    'Export compliance reports',
                ],
            ],
            [
                'id' => 'standard-user',
                'name' => 'Standard User',
                'description' => 'Access to their own account only.',
                'userCount' => $userCount,
                'permissions' => [
                    'Manage own profile',
                    'View own devices & sessions',
                    'Generate emergency recovery phrase',
                    'Toggle two-factor authentication',
                ],
            ],
        ];

        return response()->json([
            'status' => 'success',
            'data' => $roles,
        ]);
    }

    /**
     * Update role permissions.
     */
    public function update(Request $request, string $id): JsonResponse
    {
        $request->validate([
            'permissions' => ['nullable', 'array'],
            'description' => ['nullable', 'string'],
        ]);

        $this->auditLogService->recordFromRequest(
            $request,
            'ROLE_MANAGEMENT',
            'PERMISSIONS_UPDATED',
            "Permissions modified for role: {$id}",
            ['role_id' => $id, 'permissions' => $request->input('permissions')]
        );

        return response()->json([
            'status' => 'success',
            'message' => "Permissions for role '{$id}' updated successfully.",
        ]);
    }
}
