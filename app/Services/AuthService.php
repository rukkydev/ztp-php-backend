<?php

namespace App\Services;

use App\Models\Device;
use App\Models\OneTimeCode;
use App\Models\PasswordResetToken;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthService
{
    public function __construct(
        protected DeviceService $deviceService,
        protected OtpService $otpService,
        protected ResendEmailService $resendEmailService,
        protected RiskEvaluationClient $riskEvaluationClient,
        protected ThreatPreventionService $threatPreventionService,
        protected AuditLogService $auditLogService
    ) {}

    /**
     * Authenticate user credentials, check lockout, evaluate risk, handle MFA challenge.
     *
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    public function attemptLogin(string $login, string $password, Request $request): array
    {
        $loginField = filter_var($login, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

        /** @var User|null $user */
        $user = User::where($loginField, strtolower(trim($login)))->first();

        // Device resolution
        $deviceIdentifier = $request->header('X-Device-Id') ?? 'unknown-device';
        if ($this->deviceService->isDeviceBlocked($deviceIdentifier)) {
            $this->auditLogService->record(
                $user?->id,
                $user?->username ?? $login,
                $user?->type,
                'AUTHENTICATION',
                'BLOCKED_DEVICE_REJECTED',
                "Login attempt rejected from blocked device {$deviceIdentifier}",
                $request->ip()
            );

            throw ValidationException::withMessages([
                'device' => ['This device has been isolated and blocked by Zero-Trust security policies.'],
            ]);
        }

        if (! $user) {
            $this->auditLogService->record(
                null,
                $login,
                'guest',
                'AUTHENTICATION',
                'LOGIN_FAILED_UNKNOWN_USER',
                "Failed login attempt for non-existent user: {$login}",
                $request->ip()
            );

            throw ValidationException::withMessages([
                'login' => ['These credentials do not match our records.'],
            ]);
        }

        // Check if account is locked
        if ($user->isLocked()) {
            $this->auditLogService->record(
                $user->id,
                $user->username,
                $user->type,
                'AUTHENTICATION',
                'LOCKED_ACCOUNT_REJECTED',
                "Login attempt rejected for locked account: {$user->username}",
                $request->ip()
            );

            throw ValidationException::withMessages([
                'account' => ['Your account has been temporarily locked due to security anomalies. Contact SOC.'],
            ]);
        }

        // Check if account is active
        if (! $user->is_active) {
            throw ValidationException::withMessages([
                'account' => ['This account has been deactivated.'],
            ]);
        }

        // Verify password
        if (! Hash::check($password, $user->password)) {
            $user->increment('failed_login_attempts');

            if ($user->failed_login_attempts >= 5) {
                $this->threatPreventionService->lockAccountMitigation($user, null, 24);
                throw ValidationException::withMessages([
                    'account' => ['Too many failed attempts. Your account has been locked.'],
                ]);
            }

            $this->auditLogService->record(
                $user->id,
                $user->username,
                $user->type,
                'AUTHENTICATION',
                'LOGIN_FAILED_BAD_PASSWORD',
                "Bad password attempt (count: {$user->failed_login_attempts})",
                $request->ip()
            );

            throw ValidationException::withMessages([
                'password' => ['Invalid password provided.'],
            ]);
        }

        // Resolve device
        $device = $this->deviceService->resolveDevice($user, $request);

        // Evaluate risk via Microservice
        $riskLog = $this->riskEvaluationClient->evaluate($user, $device, 'LOGIN_ATTEMPT', [
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'failed_attempts' => $user->failed_login_attempts,
        ]);

        // Check if risk engine recommends blocking
        if ($riskLog->recommended_action === RiskEvaluationLog::ACTION_BLOCK) {
            $this->threatPreventionService->blockDeviceMitigation($device, $riskLog);
            throw ValidationException::withMessages([
                'device' => ['Device isolated and blocked by Zero-Trust anomaly detection.'],
            ]);
        }

        // Check if MFA is required (either enabled or stepped-up by risk engine / policy)
        $requires2fa = $user->two_factor_enabled ||
            $riskLog->recommended_action === RiskEvaluationLog::ACTION_MFA_CHALLENGE ||
            ! $device->is_trusted;

        if ($requires2fa) {
            $otp = $this->otpService->generateOtp($user, OneTimeCode::PURPOSE_LOGIN_2FA, 10);
            $this->resendEmailService->sendOtpCode($user->email, $otp, 'Zero-Trust Login Verification', 10);

            $this->auditLogService->record(
                $user->id,
                $user->username,
                $user->type,
                'AUTHENTICATION',
                '2FA_CHALLENGE_DISPATCHED',
                "Dispatched 6-digit OTP verification code to {$user->email}",
                $request->ip(),
                ['risk_score' => $riskLog->risk_score, 'device_id' => $device->id]
            );

            $isDeviceUntrustedOnly = ! $user->two_factor_enabled && ! $device->is_trusted && $riskLog->recommended_action !== RiskEvaluationLog::ACTION_MFA_CHALLENGE;

            return [
                'requires_2fa' => ! $isDeviceUntrustedOnly,
                'twoFactorRequired' => ! $isDeviceUntrustedOnly,
                'deviceVerificationRequired' => $isDeviceUntrustedOnly,
                'user_id' => $user->id,
                'email' => $this->maskEmail($user->email),
                'risk_score' => $riskLog->risk_score,
                'message' => $isDeviceUntrustedOnly
                    ? 'Unrecognized device detected. Enter the 6-digit verification code sent to your email.'
                    : 'Security verification required. Enter the 6-digit code sent to your email.',
            ];
        }

        // Successful direct login
        return $this->completeLogin($user, $device, $request, 'PASSWORD_DIRECT');
    }

    /**
     * Complete MFA or device verification step and create stateful session.
     *
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    public function verify2faLogin(int|User|string $userOrIdentifier, string $code, Request $request, bool $trustDevice = true): array
    {
        /** @var User|null $user */
        if ($userOrIdentifier instanceof User) {
            $user = $userOrIdentifier;
        } elseif (is_numeric($userOrIdentifier)) {
            $user = User::findOrFail((int) $userOrIdentifier);
        } else {
            $user = User::where('email', strtolower(trim((string) $userOrIdentifier)))->firstOrFail();
        }

        if ($user->isLocked() || ! $user->is_active) {
            throw ValidationException::withMessages([
                'code' => ['Account is locked or inactive.'],
            ]);
        }

        $isValid = $this->otpService->verifyAndConsumeOtp($user, $code, OneTimeCode::PURPOSE_LOGIN_2FA);

        if (! $isValid) {
            $this->auditLogService->record(
                $user->id,
                $user->username,
                $user->type,
                'AUTHENTICATION',
                '2FA_VERIFICATION_FAILED',
                'Invalid or expired 2FA OTP code submitted',
                $request->ip()
            );

            throw ValidationException::withMessages([
                'code' => ['The 6-digit verification code is invalid or has expired.'],
            ]);
        }

        $device = $this->deviceService->resolveDevice($user, $request);

        if ($trustDevice) {
            $device->update(['is_trusted' => true]);
        }

        return $this->completeLogin($user, $device, $request, 'MFA_VERIFIED');
    }

    /**
     * Finalize user login: reset failed attempts, update last login, establish session.
     *
     * @return array<string, mixed>
     */
    protected function completeLogin(User $user, Device $device, Request $request, string $authMethod): array
    {
        $user->update([
            'failed_login_attempts' => 0,
            'last_login_at' => Carbon::now(),
        ]);

        Auth::guard('web')->login($user, true);
        $request->session()->regenerate();

        $this->auditLogService->record(
            $user->id,
            $user->username,
            $user->type,
            'AUTHENTICATION',
            'LOGIN_SUCCESS',
            "User {$user->username} authenticated via {$authMethod}",
            $request->ip(),
            ['device_id' => $device->id, 'auth_method' => $authMethod]
        );

        return [
            'requires_2fa' => false,
            'twoFactorRequired' => false,
            'deviceVerificationRequired' => false,
            'user' => [
                'id' => $user->id,
                'username' => $user->username,
                'name' => $user->name,
                'email' => $user->email,
                'type' => $user->type,
                'role' => $user->type,
                'department' => $user->department,
                'job_title' => $user->job_title,
                'two_factor_enabled' => $user->two_factor_enabled,
                'is_active' => $user->is_active,
                'last_login_at' => $user->last_login_at,
            ],
            'device' => [
                'id' => $device->id,
                'identifier' => $device->device_identifier,
                'name' => $device->device_name,
                'is_trusted' => $device->is_trusted,
            ],
            'message' => 'Authentication successful.',
        ];
    }

    /**
     * Logout user and invalidate session.
     */
    public function logout(Request $request): void
    {
        /** @var User|null $user */
        $user = $request->user();

        if ($user) {
            $this->auditLogService->record(
                $user->id,
                $user->username,
                $user->type,
                'AUTHENTICATION',
                'LOGOUT',
                "User {$user->username} logged out",
                $request->ip()
            );
        }

        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
    }

    /**
     * Request a password reset link.
     */
    public function requestPasswordReset(string $email, Request $request): bool
    {
        $user = User::where('email', strtolower(trim($email)))->first();
        if (! $user) {
            // Do not reveal email existence
            return true;
        }

        // Invalidate old tokens
        PasswordResetToken::where('user_id', $user->id)->update(['consumed' => true]);

        $plainToken = Str::random(64);
        $tokenHash = hash('sha256', $plainToken);

        PasswordResetToken::create([
            'user_id' => $user->id,
            'token_hash' => $tokenHash,
            'consumed' => false,
            'expires_at' => Carbon::now()->addMinutes(30),
        ]);

        $frontendUrl = Config::get('app.frontend_url', env('FRONTEND_URL', 'http://localhost:5173'));
        $resetUrl = rtrim($frontendUrl, '/')."/reset-password?token={$plainToken}&email=".urlencode($user->email);

        $this->resendEmailService->sendPasswordResetLink($user->email, $resetUrl, 30);

        $this->auditLogService->record(
            $user->id,
            $user->username,
            $user->type,
            'AUTHENTICATION',
            'PASSWORD_RESET_REQUESTED',
            "Password reset link requested for {$user->email}",
            $request->ip()
        );

        return true;
    }

    /**
     * Reset password using token and revoke all active sessions.
     *
     * @throws ValidationException
     */
    public function resetPassword(string $email, string $token, string $newPassword, Request $request): bool
    {
        $user = User::where('email', strtolower(trim($email)))->first();
        if (! $user) {
            throw ValidationException::withMessages(['email' => ['Invalid password reset request.']]);
        }

        $tokenHash = hash('sha256', trim($token));

        $tokenRecord = PasswordResetToken::where('user_id', $user->id)
            ->where('token_hash', $tokenHash)
            ->where('consumed', false)
            ->where('expires_at', '>', Carbon::now())
            ->latest('id')
            ->first();

        if (! $tokenRecord) {
            throw ValidationException::withMessages(['token' => ['This password reset token is invalid or has expired.']]);
        }

        $user->update([
            'password' => $newPassword,
            'account_locked' => false,
            'locked_until' => null,
            'failed_login_attempts' => 0,
        ]);

        $tokenRecord->update(['consumed' => true]);

        // Revoke all existing sessions
        DB::table('sessions')->where('user_id', $user->id)->delete();

        $this->auditLogService->record(
            $user->id,
            $user->username,
            $user->type,
            'AUTHENTICATION',
            'PASSWORD_RESET_COMPLETED',
            "Password successfully reset for {$user->username}; sessions revoked",
            $request->ip()
        );

        $this->resendEmailService->sendSecurityAlert(
            $user->email,
            'Your Zero-Trust Password Was Changed',
            'Your password was successfully reset. All active sessions have been terminated for your security.'
        );

        return true;
    }

    /**
     * Generate an emergency recovery phrase for account lockout situations.
     */
    public function generateEmergencyRecoveryPhrase(User $user): string
    {
        $words = ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray', 'yankee', 'zulu'];
        shuffle($words);
        $phrase = implode('-', array_slice($words, 0, 6));

        $user->update([
            'recovery_phrase_hash' => hash('sha256', $phrase),
        ]);

        return $phrase;
    }

    /**
     * Recover account using emergency phrase.
     *
     * @throws ValidationException
     */
    public function recoverAccountWithPhrase(string $username, string $phrase, string $newPassword, Request $request): bool
    {
        /** @var User|null $user */
        $user = User::where('username', strtolower(trim($username)))->first();

        if (! $user || ! $user->recovery_phrase_hash) {
            throw ValidationException::withMessages(['recovery' => ['Invalid recovery credentials.']]);
        }

        if (hash('sha256', trim($phrase)) !== $user->recovery_phrase_hash) {
            throw ValidationException::withMessages(['recovery' => ['Invalid emergency recovery phrase.']]);
        }

        $user->update([
            'password' => $newPassword,
            'account_locked' => false,
            'locked_until' => null,
            'failed_login_attempts' => 0,
            'recovery_phrase_hash' => null, // One-time recovery
        ]);

        DB::table('sessions')->where('user_id', $user->id)->delete();

        $this->auditLogService->record(
            $user->id,
            $user->username,
            $user->type,
            'AUTHENTICATION',
            'EMERGENCY_ACCOUNT_RECOVERY',
            "Account recovered using emergency phrase for {$user->username}",
            $request->ip()
        );

        return true;
    }

    /**
     * Mask email for display in MFA challenge (e.g. j***e@domain.com).
     */
    protected function maskEmail(string $email): string
    {
        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            return $email;
        }

        $name = $parts[0];
        $domain = $parts[1];

        $length = strlen($name);
        if ($length <= 2) {
            $maskedName = substr($name, 0, 1).'*';
        } else {
            $maskedName = substr($name, 0, 1).str_repeat('*', max(1, $length - 2)).substr($name, -1);
        }

        return $maskedName.'@'.$domain;
    }
}
