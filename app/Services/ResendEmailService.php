<?php

namespace App\Services;

use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Resend;

class ResendEmailService
{
    protected ?string $apiKey;

    protected string $fromEmail;

    public function __construct()
    {
        $this->apiKey = Config::get('services.resend.key');
        $this->fromEmail = Config::get('services.resend.from', 'onboarding@resend.dev');
    }

    /**
     * Send 6-digit OTP verification code via Resend.
     */
    public function sendOtpCode(string $toEmail, string $code, string $purpose = 'Login Verification', int $expiryMinutes = 10): bool
    {
        $subject = "Your Zero-Trust Security Code: {$code}";
        $html = "
        <div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; background: #0f172a; color: #f8fafc; border-radius: 12px; border: 1px solid #1e293b;\">
            <h2 style=\"color: #38bdf8; margin-top: 0;\">Zero-Trust Network Access</h2>
            <p style=\"font-size: 16px; color: #cbd5e1;\">A security verification was triggered for: <strong>{$purpose}</strong>.</p>
            <div style=\"background: #1e293b; padding: 18px; border-radius: 8px; text-align: center; margin: 24px 0; border: 1px dashed #38bdf8;\">
                <span style=\"font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #38bdf8;\">{$code}</span>
            </div>
            <p style=\"font-size: 14px; color: #94a3b8;\">This single-use code will expire in <strong>{$expiryMinutes} minutes</strong>. If you did not initiate this request, your credentials may be compromised. Please notify your Security Operations Center immediately.</p>
            <hr style=\"border: 0; border-top: 1px solid #334155; margin: 24px 0;\" />
            <p style=\"font-size: 12px; color: #64748b;\">Zero-Trust Continuous Threat Prevention System &bull; Confidential</p>
        </div>
        ";

        return $this->dispatchEmail($toEmail, $subject, $html);
    }

    /**
     * Send Password Reset link.
     */
    public function sendPasswordResetLink(string $toEmail, string $resetUrl, int $expiryMinutes = 30): bool
    {
        $subject = 'Zero-Trust Security: Password Reset Request';
        $html = "
        <div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; background: #0f172a; color: #f8fafc; border-radius: 12px; border: 1px solid #1e293b;\">
            <h2 style=\"color: #38bdf8; margin-top: 0;\">Zero-Trust Access Management</h2>
            <p style=\"font-size: 16px; color: #cbd5e1;\">We received a request to reset your password. All active sessions will be terminated upon reset.</p>
            <div style=\"text-align: center; margin: 30px 0;\">
                <a href=\"{$resetUrl}\" style=\"background: #0284c7; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; display: inline-block;\">Reset Password</a>
            </div>
            <p style=\"font-size: 14px; color: #94a3b8;\">This link is valid for <strong>{$expiryMinutes} minutes</strong>. If you did not request this change, please contact SOC immediately.</p>
            <hr style=\"border: 0; border-top: 1px solid #334155; margin: 24px 0;\" />
            <p style=\"font-size: 12px; color: #64748b;\">Zero-Trust Continuous Threat Prevention System &bull; Confidential</p>
        </div>
        ";

        return $this->dispatchEmail($toEmail, $subject, $html);
    }

    /**
     * Send Security Alert (e.g. 2FA disabled, suspicious login, device blocked).
     */
    public function sendSecurityAlert(string $toEmail, string $alertTitle, string $alertMessage, array $metadata = []): bool
    {
        $subject = "SECURITY ALERT: {$alertTitle}";
        $metaHtml = '';
        if (! empty($metadata)) {
            $metaHtml = '<ul style="background: #1e293b; padding: 16px 24px; border-radius: 8px; color: #94a3b8; font-size: 13px;">';
            foreach ($metadata as $key => $val) {
                $metaHtml .= '<li><strong>'.htmlspecialchars((string) $key).':</strong> '.htmlspecialchars((string) $val).'</li>';
            }
            $metaHtml .= '</ul>';
        }

        $html = "
        <div style=\"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 24px; background: #0f172a; color: #f8fafc; border-radius: 12px; border: 1px solid #ef4444;\">
            <h2 style=\"color: #ef4444; margin-top: 0;\">⚠️ Security Notification</h2>
            <h3 style=\"color: #f8fafc;\">{$alertTitle}</h3>
            <p style=\"font-size: 15px; color: #cbd5e1;\">{$alertMessage}</p>
            {$metaHtml}
            <p style=\"font-size: 13px; color: #94a3b8; margin-top: 20px;\">If this action was not authorized by you, your account may be under attack. Please contact security administration immediately.</p>
        </div>
        ";

        return $this->dispatchEmail($toEmail, $subject, $html);
    }

    /**
     * Internal email dispatcher with Resend API, Laravel Mail (Mailhog), and logging fallback.
     */
    protected function dispatchEmail(string $to, string $subject, string $html): bool
    {
        // Skip live network during testing
        if (Config::get('app.env') === 'testing') {
            Log::info('Email dispatch skipped in testing environment', ['to' => $to, 'subject' => $subject]);

            return true;
        }

        // 1. Resend API delivery if key configured and in production
        if (! empty($this->apiKey) && class_exists(Resend::class) && Config::get('app.env') === 'production') {
            try {
                $resend = Resend::client($this->apiKey);
                $resend->emails->send([
                    'from' => $this->fromEmail,
                    'to' => [$to],
                    'subject' => $subject,
                    'html' => $html,
                ]);

                Log::info('Resend email dispatched successfully', ['to' => $to, 'subject' => $subject]);

                return true;
            } catch (Exception $e) {
                Log::error('Resend email delivery failed: '.$e->getMessage(), [
                    'to' => $to,
                    'subject' => $subject,
                    'exception' => $e,
                ]);
            }
        }

        // 2. Local Mailhog / SMTP / Laravel Mailer dispatch
        try {
            Mail::html($html, function ($message) use ($to, $subject) {
                $message->to($to)
                    ->from($this->fromEmail, Config::get('app.name', 'Zero-Trust Security'))
                    ->subject($subject);
            });

            Log::info('Email dispatched via Laravel Mailer (Mailhog/SMTP)', ['to' => $to, 'subject' => $subject]);

            return true;
        } catch (Exception $e) {
            // 3. Graceful fallback to log if Mailhog SMTP daemon is offline
            Log::info('ResendEmailService [Local/Fallback Simulation]', [
                'to' => $to,
                'from' => $this->fromEmail,
                'subject' => $subject,
                'html_preview' => strip_tags(substr($html, 0, 200)),
                'smtp_notice' => $e->getMessage(),
            ]);

            return true;
        }
    }
}
