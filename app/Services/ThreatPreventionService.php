<?php

namespace App\Services;

use App\Events\ThreatMitigationTriggered;
use App\Models\Device;
use App\Models\ResponseAction;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class ThreatPreventionService
{
    public function __construct(
        protected DeviceService $deviceService,
        protected ResendEmailService $resendEmailService,
        protected AuditLogService $auditLogService
    ) {}

    /**
     * Enforce automated mitigation based on an evaluated risk log.
     */
    public function enforceMitigation(RiskEvaluationLog $riskLog): ?ResponseAction
    {
        $action = $riskLog->recommended_action;
        $user = $riskLog->user;
        $device = $riskLog->device;

        if ($action === RiskEvaluationLog::ACTION_ALLOW) {
            return null;
        }

        $correlationId = $riskLog->correlation_id;

        if ($action === RiskEvaluationLog::ACTION_BLOCK && $device) {
            return $this->blockDeviceMitigation($device, $riskLog);
        }

        if ($action === RiskEvaluationLog::ACTION_RESTRICT && $user) {
            return $this->lockAccountMitigation($user, $riskLog);
        }

        if ($action === RiskEvaluationLog::ACTION_MFA_CHALLENGE && $user) {
            return $this->forceMfaMitigation($user, $riskLog);
        }

        return null;
    }

    /**
     * Mitigate by blocking a device.
     */
    public function blockDeviceMitigation(Device $device, ?RiskEvaluationLog $riskLog = null): ResponseAction
    {
        $correlationId = $riskLog?->correlation_id ?? (string) Str::uuid();

        $device->update(['is_blocked' => true]);

        // Terminate sessions associated with this user
        if ($device->user_id) {
            DB::table('sessions')->where('user_id', $device->user_id)->delete();
        }

        $responseAction = ResponseAction::create([
            'correlation_id' => $correlationId,
            'target_type' => ResponseAction::TARGET_DEVICE,
            'target_identifier' => $device->device_identifier,
            'action_taken' => ResponseAction::ACTION_BLOCK_DEVICE,
            'status' => ResponseAction::STATUS_EXECUTED,
            'triggered_by_risk_log_id' => $riskLog?->id,
            'executed_at' => Carbon::now(),
        ]);

        if ($riskLog) {
            $riskLog->update(['enforced_action' => ResponseAction::ACTION_BLOCK_DEVICE]);
        }

        // Notify user if email available
        if ($device->user && $device->user->email) {
            $this->resendEmailService->sendSecurityAlert(
                $device->user->email,
                'Device Access Blocked Due to Security Risk',
                "Your device ({$device->device_name}) has been isolated and blocked after high-risk anomaly detection.",
                [
                    'Device ID' => $device->device_identifier,
                    'IP Address' => $device->ip_address,
                    'Time' => Carbon::now()->toDateTimeString(),
                ]
            );
        }

        $this->auditLogService->record(
            $device->user_id,
            $device->user?->username ?? 'system',
            $device->user?->type ?? 'system',
            'THREAT_RESPONSE',
            'DEVICE_BLOCKED',
            "Automated mitigation blocked device {$device->device_identifier}",
            $device->ip_address,
            ['device_id' => $device->id, 'correlation_id' => $correlationId]
        );

        event(new ThreatMitigationTriggered($responseAction, $riskLog));

        return $responseAction;
    }

    /**
     * Mitigate by locking user account.
     */
    public function lockAccountMitigation(User $user, ?RiskEvaluationLog $riskLog = null, int $lockHours = 24): ResponseAction
    {
        $correlationId = $riskLog?->correlation_id ?? (string) Str::uuid();

        $user->update([
            'account_locked' => true,
            'locked_until' => Carbon::now()->addHours($lockHours),
        ]);

        // Invalidate all active sessions for this user
        DB::table('sessions')->where('user_id', $user->id)->delete();

        $responseAction = ResponseAction::create([
            'correlation_id' => $correlationId,
            'target_type' => ResponseAction::TARGET_USER,
            'target_identifier' => (string) $user->id,
            'action_taken' => ResponseAction::ACTION_LOCK_ACCOUNT,
            'status' => ResponseAction::STATUS_EXECUTED,
            'triggered_by_risk_log_id' => $riskLog?->id,
            'executed_at' => Carbon::now(),
        ]);

        if ($riskLog) {
            $riskLog->update(['enforced_action' => ResponseAction::ACTION_LOCK_ACCOUNT]);
        }

        $this->resendEmailService->sendSecurityAlert(
            $user->email,
            'Account Locked Due to Suspicious Behavior',
            'Your account has been temporarily locked by the Zero-Trust Threat Prevention engine.',
            [
                'Username' => $user->username,
                'Lock Duration' => "{$lockHours} hours",
                'Time' => Carbon::now()->toDateTimeString(),
            ]
        );

        $this->auditLogService->record(
            $user->id,
            $user->username,
            $user->type,
            'THREAT_RESPONSE',
            'ACCOUNT_LOCKED',
            "Automated mitigation locked account for user {$user->username}",
            null,
            ['user_id' => $user->id, 'correlation_id' => $correlationId]
        );

        event(new ThreatMitigationTriggered($responseAction, $riskLog));

        return $responseAction;
    }

    /**
     * Mitigate by terminating all sessions.
     */
    public function killSessionsMitigation(User $user, ?RiskEvaluationLog $riskLog = null): ResponseAction
    {
        $correlationId = $riskLog?->correlation_id ?? (string) Str::uuid();

        DB::table('sessions')->where('user_id', $user->id)->delete();

        $responseAction = ResponseAction::create([
            'correlation_id' => $correlationId,
            'target_type' => ResponseAction::TARGET_SESSION,
            'target_identifier' => (string) $user->id,
            'action_taken' => ResponseAction::ACTION_KILL_SESSIONS,
            'status' => ResponseAction::STATUS_EXECUTED,
            'triggered_by_risk_log_id' => $riskLog?->id,
            'executed_at' => Carbon::now(),
        ]);

        if ($riskLog) {
            $riskLog->update(['enforced_action' => ResponseAction::ACTION_KILL_SESSIONS]);
        }

        return $responseAction;
    }

    /**
     * Force step-up MFA challenge.
     */
    public function forceMfaMitigation(User $user, ?RiskEvaluationLog $riskLog = null): ResponseAction
    {
        $correlationId = $riskLog?->correlation_id ?? (string) Str::uuid();

        $responseAction = ResponseAction::create([
            'correlation_id' => $correlationId,
            'target_type' => ResponseAction::TARGET_USER,
            'target_identifier' => (string) $user->id,
            'action_taken' => ResponseAction::ACTION_FORCE_MFA,
            'status' => ResponseAction::STATUS_EXECUTED,
            'triggered_by_risk_log_id' => $riskLog?->id,
            'executed_at' => Carbon::now(),
        ]);

        if ($riskLog) {
            $riskLog->update(['enforced_action' => ResponseAction::ACTION_FORCE_MFA]);
        }

        return $responseAction;
    }

    /**
     * Revert or override a mitigation action (Analyst / Admin action).
     */
    public function revertAction(ResponseAction $responseAction, ?User $actor = null): bool
    {
        if ($responseAction->action_taken === ResponseAction::ACTION_BLOCK_DEVICE) {
            Device::where('device_identifier', $responseAction->target_identifier)->update(['is_blocked' => false]);
        } elseif ($responseAction->action_taken === ResponseAction::ACTION_LOCK_ACCOUNT) {
            User::where('id', $responseAction->target_identifier)->update([
                'account_locked' => false,
                'locked_until' => null,
                'failed_login_attempts' => 0,
            ]);
        }

        $responseAction->update(['status' => ResponseAction::STATUS_REVERTED]);

        $this->auditLogService->record(
            $actor?->id,
            $actor?->username ?? 'system',
            $actor?->type ?? 'security_analyst',
            'THREAT_RESPONSE',
            'ACTION_REVERTED',
            "Mitigation action {$responseAction->action_taken} on target {$responseAction->target_identifier} reverted",
            null,
            ['action_id' => $responseAction->id]
        );

        return true;
    }
}
