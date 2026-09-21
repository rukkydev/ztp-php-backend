<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\VerifyOtpRequest;
use App\Models\OneTimeCode;
use App\Models\User;
use App\Services\AuditLogService;
use App\Services\AuthService;
use App\Services\OtpService;
use App\Services\ResendEmailService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function __construct(
        protected AuthService $authService,
        protected OtpService $otpService,
        protected ResendEmailService $resendEmailService,
        protected AuditLogService $auditLogService
    ) {}

    /**
     * Handle inbound login request.
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $result = $this->authService->attemptLogin(
            $validated['login'],
            $validated['password'],
            $request
        );

        return response()->json([
            'status' => 'success',
            'data' => $result,
        ]);
    }

    /**
     * Handle 2FA OTP verification code submission.
     */
    public function verifyOtp(VerifyOtpRequest $request): JsonResponse
    {
        $validated = $request->validated();
        $target = $validated['user_id'] ?? $validated['email'];
        $remember = $validated['rememberDevice'] ?? $validated['remember_device'] ?? true;

        $result = $this->authService->verify2faLogin(
            $target,
            $validated['code'],
            $request,
            (bool) $remember
        );

        return response()->json([
            'status' => 'success',
            'data' => $result,
        ]);
    }

    /**
     * Handle device verification submission (endpoint alias for frontend).
     */
    public function verifyDevice(VerifyOtpRequest $request): JsonResponse
    {
        return $this->verifyOtp($request);
    }

    /**
     * Handle 2FA submission (endpoint alias for frontend).
     */
    public function verify2fa(VerifyOtpRequest $request): JsonResponse
    {
        return $this->verifyOtp($request);
    }

    /**
     * Resend 2FA / Device verification code.
     */
    public function resendOtp(Request $request): JsonResponse
    {
        $request->validate([
            'user_id' => ['required_without:email', 'integer', 'exists:users,id'],
            'email' => ['required_without:user_id', 'email', 'exists:users,email'],
        ]);

        /** @var User $user */
        if ($request->filled('user_id')) {
            $user = User::findOrFail($request->input('user_id'));
        } else {
            $user = User::where('email', strtolower(trim((string) $request->input('email'))))->firstOrFail();
        }

        if ($user->isLocked() || ! $user->is_active) {
            throw ValidationException::withMessages(['email' => ['Account is locked or inactive.']]);
        }

        $code = $this->otpService->generateOtp($user, OneTimeCode::PURPOSE_LOGIN_2FA, 10);
        $this->resendEmailService->sendOtpCode($user->email, $code, 'Zero-Trust Login Verification', 10);

        return response()->json([
            'status' => 'success',
            'message' => 'New verification code has been dispatched.',
        ]);
    }

    /**
     * Resend device verification code (alias for frontend).
     */
    public function resendDeviceOtp(Request $request): JsonResponse
    {
        return $this->resendOtp($request);
    }

    /**
     * Resend 2FA verification code (alias for frontend).
     */
    public function resend2faOtp(Request $request): JsonResponse
    {
        return $this->resendOtp($request);
    }

    /**
     * Get the authenticated user's profile and active context.
     */
    public function me(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        return response()->json([
            'status' => 'success',
            'data' => [
                'id' => $user->id,
                'username' => $user->username,
                'name' => $user->name,
                'email' => $user->email,
                'type' => $user->type,
                'role' => $user->type,
                'department' => $user->department,
                'job_title' => $user->job_title,
                'avatar_url' => $user->avatar_url,
                'is_active' => $user->is_active,
                'two_factor_enabled' => $user->two_factor_enabled,
                'last_login_at' => $user->last_login_at,
            ],
        ]);
    }

    /**
     * Invalidate session and log user out.
     */
    public function logout(Request $request): JsonResponse
    {
        $this->authService->logout($request);

        return response()->json([
            'status' => 'success',
            'message' => 'Logged out successfully.',
        ]);
    }

    /**
     * Handle public user self-registration.
     */
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'username' => ['required', 'string', 'min:3', 'max:50', 'alpha_dash', 'unique:users,username'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', 'min:8', 'max:100'],
            'name' => ['nullable', 'string', 'max:100'],
        ]);

        $user = User::create([
            'username' => strtolower(trim($validated['username'])),
            'email' => strtolower(trim($validated['email'])),
            'password' => $validated['password'],
            'name' => $validated['name'] ?? trim($validated['username']),
            'type' => User::TYPE_USER,
            'is_active' => true,
        ]);

        $this->auditLogService->record(
            $user->id,
            $user->username,
            $user->type,
            'AUTHENTICATION',
            'USER_REGISTERED',
            "New user {$user->username} self-registered account",
            $request->ip(),
            ['user_id' => $user->id, 'email' => $user->email]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Account created successfully. You may now sign in.',
            'data' => [
                'id' => $user->id,
                'username' => $user->username,
                'email' => $user->email,
            ],
        ], 201);
    }
}
