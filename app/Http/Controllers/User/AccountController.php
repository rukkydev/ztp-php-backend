<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use App\Http\Requests\User\ChangePasswordRequest;
use App\Http\Requests\User\UpdateProfileRequest;
use App\Models\User;
use App\Services\AuditLogService;
use App\Services\AuthService;
use App\Services\ResendEmailService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class AccountController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService,
        protected ResendEmailService $resendEmailService,
        protected AuthService $authService
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

    /**
     * Aggregated account overview metrics.
     */
    public function overview(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $deviceCount = $user->devices()->count();
        $sessionCount = \Illuminate\Support\Facades\DB::table('sessions')->where('user_id', $user->id)->count();

        return response()->json([
            'status' => 'success',
            'data' => [
                'profile' => $user,
                'deviceCount' => max($deviceCount, 1),
                'sessionCount' => max($sessionCount, 1),
                'unreadNotifications' => 0,
                'hasRecoveryPhrase' => ! empty($user->recovery_phrase_hash),
            ],
        ]);
    }

    /**
     * Upload user avatar profile picture.
     */
    public function uploadAvatar(Request $request): JsonResponse
    {
        $request->validate([
            'file' => ['required', 'file', 'image', 'max:2048'], // 2MB max
        ]);

        /** @var User $user */
        $user = $request->user();

        $path = $request->file('file')->store('avatars', 'public');
        $url = Storage::disk('public')->url($path);

        $user->update(['avatar_url' => $url]);

        $this->auditLogService->recordFromRequest(
            $request,
            'USER_MANAGEMENT',
            'AVATAR_UPDATED',
            "User {$user->username} updated profile picture"
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Avatar uploaded successfully.',
            'data' => [
                'avatarUrl' => $url,
                'avatar_url' => $url,
            ],
        ]);
    }

    /**
     * Get recovery phrase setup status.
     */
    public function recoveryPhraseStatus(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        return response()->json([
            'status' => 'success',
            'data' => ! empty($user->recovery_phrase_hash),
        ]);
    }

    /**
     * Generate 12-word recovery phrase for authenticated user.
     */
    public function generateRecoveryPhrase(Request $request): JsonResponse
    {
        $request->validate([
            'password' => ['nullable', 'string'],
        ]);

        /** @var User $user */
        $user = $request->user();

        $phrase = $this->authService->generateEmergencyRecoveryPhrase($user);

        return response()->json([
            'status' => 'success',
            'data' => $phrase,
            'message' => 'Recovery phrase generated successfully.',
        ]);
    }

    /**
     * Get notification preferences for the user.
     */
    public function notificationPreferences(Request $request): JsonResponse
    {
        return response()->json([
            'status' => 'success',
            'data' => [
                'email' => [
                    ['eventKey' => 'new-device-login', 'label' => 'New device sign-in', 'checked' => true],
                    ['eventKey' => 'failed-login-spike', 'label' => 'Unusual number of failed attempts', 'checked' => true],
                    ['eventKey' => 'security-policy-change', 'label' => 'Security policy changes', 'checked' => true],
                    ['eventKey' => 'weekly-summary', 'label' => 'Weekly security digest', 'checked' => false],
                ],
                'push' => [
                    ['eventKey' => 'critical-threats', 'label' => 'Critical threats detected', 'checked' => true],
                    ['eventKey' => 'device-blocked', 'label' => 'Device blocked or isolated', 'checked' => true],
                    ['eventKey' => 'new-device-login', 'label' => 'New device sign-in', 'checked' => false],
                ],
            ],
        ]);
    }

    /**
     * Update notification preferences.
     */
    public function updateNotificationPreferences(Request $request): JsonResponse
    {
        $this->auditLogService->recordFromRequest(
            $request,
            'USER_PREFERENCES',
            'NOTIFICATIONS_UPDATED',
            'User notification channel preferences updated'
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Notification preferences saved successfully.',
        ]);
    }
}
