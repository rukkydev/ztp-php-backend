<?php

namespace App\Services;

use App\Models\Device;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Throwable;

class RiskEvaluationClient
{
    protected string $baseUrl;

    protected int $timeoutMs;

    protected bool $enabled;

    public function __construct()
    {
        $this->baseUrl = (string) Config::get('services.risk_engine.base_url', 'http://127.0.0.1:8081');
        $this->timeoutMs = (int) Config::get('services.risk_engine.timeout_ms', 400);
        $this->enabled = (bool) Config::get('services.risk_engine.enabled', true);
    }

    /**
     * Evaluate risk for an action or request.
     * Supports both model-based parameters and array payload formats.
     *
     * @param  User|array<string, mixed>|null  $userOrParams
     * @param  array<string, mixed>  $context
     */
    public function evaluate(
        User|array|null $userOrParams = null,
        ?Device $device = null,
        string $eventType = 'LOGIN_ATTEMPT',
        array $context = []
    ): RiskEvaluationLog {
        $startTime = microtime(true);

        if (is_array($userOrParams)) {
            $params = $userOrParams;
            $correlationId = (string) ($params['correlation_id'] ?? Str::uuid());
            $userId = isset($params['user_id']) ? (int) $params['user_id'] : null;
            $username = isset($params['username']) ? (string) $params['username'] : null;
            $userType = (string) ($params['user_type'] ?? 'user');
            $deviceId = isset($params['device_id']) ? (int) $params['device_id'] : null;
            $deviceIdentifier = isset($params['device_identifier']) ? (string) $params['device_identifier'] : null;
            $isDeviceTrusted = (bool) ($params['is_device_trusted'] ?? false);
            $isDeviceBlocked = (bool) ($params['is_device_blocked'] ?? false);
            $eventType = (string) ($params['event_type'] ?? 'API_ACCESS');
            $ip = (string) ($params['ip_address'] ?? '127.0.0.1');
            $userAgent = isset($params['user_agent']) ? (string) $params['user_agent'] : null;
            $innerContext = (array) ($params['context'] ?? []);
            $timestamp = (string) ($params['timestamp'] ?? Carbon::now('UTC')->toIso8601String());
        } else {
            /** @var User|null $user */
            $user = $userOrParams;
            $correlationId = (string) ($context['correlation_id'] ?? Str::uuid());
            $userId = $user?->id;
            $username = $user?->username ?? ($context['username'] ?? null);
            $userType = $user?->type ?? ($context['user_type'] ?? 'user');
            $deviceId = $device?->id;
            $deviceIdentifier = $device?->device_identifier ?? ($context['device_identifier'] ?? null);
            $isDeviceTrusted = (bool) ($device?->is_trusted ?? ($context['is_device_trusted'] ?? false));
            $isDeviceBlocked = (bool) ($device?->is_blocked ?? ($context['is_device_blocked'] ?? false));
            $ip = (string) ($context['ip_address'] ?? ($device?->ip_address ?? '127.0.0.1'));
            $userAgent = isset($context['user_agent']) ? (string) $context['user_agent'] : null;
            $innerContext = $context;
            $timestamp = Carbon::now('UTC')->toIso8601String();
        }

        $payload = [
            'correlation_id' => $correlationId,
            'user_id' => $userId,
            'username' => $username,
            'user_type' => $userType,
            'device_id' => $deviceId,
            'device_identifier' => $deviceIdentifier,
            'is_device_trusted' => $isDeviceTrusted,
            'is_device_blocked' => $isDeviceBlocked,
            'event_type' => $eventType,
            'ip_address' => $ip,
            'user_agent' => $userAgent,
            'context' => $innerContext,
            'timestamp' => $timestamp,
        ];

        // Fail-open immediately if disabled in configuration
        if (! $this->enabled) {
            $durationMs = round((microtime(true) - $startTime) * 1000, 2);

            return RiskEvaluationLog::create([
                'correlation_id' => $correlationId,
                'user_id' => $userId,
                'username' => $username,
                'device_id' => $deviceId,
                'event_type' => $eventType,
                'risk_score' => 0,
                'risk_level' => RiskEvaluationLog::LEVEL_LOW,
                'recommended_action' => RiskEvaluationLog::ACTION_ALLOW,
                'enforced_action' => null,
                'evaluate_reached' => false,
                'engine_version' => '1.0.0',
                'reasons_json' => ['engine_disabled'],
                'ip_address' => $ip,
                'latency_ms' => $durationMs,
                'evaluated_at' => Carbon::now(),
            ]);
        }

        $timeoutSeconds = max(0.05, $this->timeoutMs / 1000);
        $response = null;

        try {
            $response = Http::timeout($timeoutSeconds)
                ->connectTimeout($timeoutSeconds)
                ->asJson()
                ->acceptJson()
                ->post(rtrim($this->baseUrl, '/').'/risk/evaluate', $payload);
        } catch (Throwable $e) {
            // Strict Fail-Open resilience: log warning and proceed safely
            Log::warning('Risk evaluation microservice unreachable or timed out (fail-open triggered): '.$e->getMessage(), [
                'correlation_id' => $correlationId,
                'timeout_ms' => $this->timeoutMs,
            ]);
        }

        $durationMs = round((microtime(true) - $startTime) * 1000, 2);

        if ($response && $response->successful()) {
            $data = $response->json();

            return RiskEvaluationLog::create([
                'correlation_id' => $data['correlation_id'] ?? $correlationId,
                'user_id' => $userId,
                'username' => $username,
                'device_id' => $deviceId,
                'event_type' => $eventType,
                'risk_score' => (int) ($data['risk_score'] ?? 0),
                'risk_level' => (string) ($data['risk_level'] ?? RiskEvaluationLog::LEVEL_LOW),
                'recommended_action' => (string) ($data['recommended_action'] ?? RiskEvaluationLog::ACTION_ALLOW),
                'enforced_action' => null,
                'evaluate_reached' => true,
                'engine_version' => (string) ($data['engine_version'] ?? '1.0.0'),
                'reasons_json' => (array) ($data['reasons'] ?? ($data['reasons_json'] ?? [])),
                'ip_address' => $ip,
                'latency_ms' => $durationMs,
                'evaluated_at' => Carbon::now(),
            ]);
        }

        if ($response && ! $response->successful()) {
            Log::warning("Risk engine returned HTTP {$response->status()}", [
                'correlation_id' => $correlationId,
                'body' => $response->body(),
            ]);
        }

        $durationMs = round((microtime(true) - $startTime) * 1000, 2);

        // FAIL-OPEN FALLBACK: Never block business traffic due to infrastructure timeout
        return RiskEvaluationLog::create([
            'correlation_id' => $correlationId,
            'user_id' => $userId,
            'username' => $username,
            'device_id' => $deviceId,
            'event_type' => $eventType,
            'risk_score' => 0,
            'risk_level' => RiskEvaluationLog::LEVEL_LOW,
            'recommended_action' => RiskEvaluationLog::ACTION_ALLOW,
            'enforced_action' => null,
            'evaluate_reached' => false,
            'engine_version' => '1.0.0',
            'reasons_json' => ['engine_fail_open_timeout'],
            'ip_address' => $ip,
            'latency_ms' => $durationMs,
            'evaluated_at' => Carbon::now(),
        ]);
    }

    /**
     * Raw array evaluation method matching Section 6.1 handoff interface.
     *
     * @param  array<string, mixed>  $params
     * @return array<string, mixed>
     */
    public function evaluateRaw(array $params): array
    {
        $log = $this->evaluate($params);

        return [
            'correlation_id' => $log->correlation_id,
            'risk_score' => $log->risk_score,
            'risk_level' => $log->risk_level,
            'recommended_action' => $log->recommended_action,
            'reasons' => $log->reasons_json ?? [],
            'engine_version' => $log->engine_version,
            'evaluate_reached' => $log->evaluate_reached,
            'latency_ms' => $log->latency_ms,
        ];
    }

    /**
     * Probe microservice liveness.
     *
     * @return array<string, mixed>
     */
    public function health(): array
    {
        try {
            $response = Http::timeout(1)->get(rtrim($this->baseUrl, '/').'/health');

            return $response->json() ?? ['status' => 'error'];
        } catch (Throwable $e) {
            return [
                'status' => 'unreachable',
                'service' => 'risk-engine',
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Probe microservice readiness (ML model loaded in RAM).
     *
     * @return array<string, mixed>
     */
    public function ready(): array
    {
        try {
            $response = Http::timeout(1)->get(rtrim($this->baseUrl, '/').'/ready');

            return $response->json() ?? ['status' => 'error'];
        } catch (Throwable $e) {
            return [
                'status' => 'unreachable',
                'model_loaded' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Determine whether the risk engine is healthy and accepting traffic.
     */
    public function isHealthy(): bool
    {
        return ($this->health()['status'] ?? '') === 'ok';
    }

    /**
     * Determine whether the risk engine has its ML model loaded and is ready.
     */
    public function isReady(): bool
    {
        $ready = $this->ready();

        return ($ready['status'] ?? '') === 'ready' && ($ready['model_loaded'] ?? false) === true;
    }
}
