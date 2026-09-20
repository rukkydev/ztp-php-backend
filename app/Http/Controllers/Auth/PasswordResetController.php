<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\ForgotPasswordRequest;
use App\Http\Requests\Auth\ResetPasswordRequest;
use App\Services\AuthService;
use Illuminate\Http\JsonResponse;

class PasswordResetController extends Controller
{
    public function __construct(
        protected AuthService $authService
    ) {}

    /**
     * Send a password reset link to the given user.
     */
    public function forgotPassword(ForgotPasswordRequest $request): JsonResponse
    {
        $this->authService->requestPasswordReset($request->validated('email'), $request);

        return response()->json([
            'status' => 'success',
            'message' => 'If an account exists with this email, a password reset link has been dispatched.',
        ]);
    }

    /**
     * Reset user password and revoke existing sessions.
     */
    public function resetPassword(ResetPasswordRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $this->authService->resetPassword(
            $validated['email'],
            $validated['token'],
            $validated['password'],
            $request
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Your password has been successfully reset. You may now log in.',
        ]);
    }
}
