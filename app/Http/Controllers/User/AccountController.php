<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use App\Http\Requests\User\ChangePasswordRequest;
use App\Http\Requests\User\UpdateProfileRequest;
use App\Models\User;
use App\Services\AuditLogService;
use App\Services\ResendEmailService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AccountController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService,
        protected ResendEmailService $resendEmailService
    ) {}

    /**
     * Get authenticated user profile with device stats.
     */
    public function profile(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $user->loadCount(['devices', 'sightings', 'accessRequests']);

        return response()->json([
            'status' => 'success',
            'data' => $user,
        ]);
    }

    /**
     * Update user profile information.
     */
    public function updateProfile(UpdateProfileRequest $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $user->update($request->validated());

        $this->auditLogService->recordFromRequest(
            $request,
            'USER_MANAGEMENT',
            'PROFILE_UPDATED',
            "User {$user->username} updated profile"
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Profile updated successfully.',
            'data' => $user->fresh(),
        ]);
    }

    /**
     * Change account password.
     */
    public function changePassword(ChangePasswordRequest $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $user->update([
            'password' => $request->validated('password'),
        ]);

        $this->auditLogService->recordFromRequest(
            $request,
            'AUTHENTICATION',
            'PASSWORD_CHANGED',
            "User {$user->username} changed their password"
        );

        $this->resendEmailService->sendSecurityAlert(
            $user->email,
            'Security Notice: Password Updated',
            'Your account password was recently changed. If you did not perform this change, contact security immediately.'
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Password updated successfully.',
        ]);
    }

    /**
     * Toggle Two-Factor Authentication state.
     */
    public function toggleTwoFactor(Request $request): JsonResponse
    {
        $request->validate([
            'enabled' => ['required', 'boolean'],
        ]);

        /** @var User $user */
        $user = $request->user();
        $enabled = $request->boolean('enabled');

        $user->update(['two_factor_enabled' => $enabled]);

        $statusStr = $enabled ? 'enabled' : 'disabled';

        $this->auditLogService->recordFromRequest(
            $request,
            'AUTHENTICATION',
            '2FA_STATE_TOGGLED',
            "User {$user->username} {$statusStr} Two-Factor Authentication"
        );

        if (! $enabled) {
            $this->resendEmailService->sendSecurityAlert(
                $user->email,
                'Security Warning: Two-Factor Authentication Disabled',
                'Two-Factor Authentication was deactivated on your account. We strongly recommend keeping 2FA enabled.'
            );
        }

        return response()->json([
            'status' => 'success',
            'message' => "Two-Factor Authentication has been {$statusStr}.",
            'two_factor_enabled' => $enabled,
        ]);
    }
}
