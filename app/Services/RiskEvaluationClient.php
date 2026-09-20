<?php

namespace App\Services;

use App\Models\Device;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use Carbon\Carbon;
use Exception;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class RiskEvaluationClient
{
    protected string $baseUrl;

    protected int $timeoutMs;

    public function __construct()
    {
        $this->baseUrl = Config::get('services.risk_engine.base_url', 'http://127.0.0.1:8081');
        $this->timeoutMs = (int) Config::get('services.risk_engine.timeout_ms', 400);
    }

    /**
     * Evaluate risk for an action or request.
     *
     * @param  array<string, mixed>  $context
     */
    public function evaluate(
        ?User $user,
        ?Device $device,
        string $eventType,
        array $context = []
    ): RiskEvaluationLog {
        $correlationId = (string) Str::uuid();
        $ip = $context['ip_address'] ?? ($device?->ip_address ?? '127.0.0.1');

        $payload = [
            'correlation_id' => $correlationId,
            'user_id' => $user?->id,
            'username' => $user?->username,
            'user_type' => $user?->type,
            'device_id' => $device?->id,
            'device_identifier' => $device?->device_identifier,
            'is_device_trusted' => $device?->is_trusted ?? false,
            'is_device_blocked' => $device?->is_blocked ?? false,
            'event_type' => $eventType,
            'ip_address' => $ip,
            'user_agent' => $context['user_agent'] ?? null,
            'context' => $context,
            'timestamp' => Carbon::now()->toIso8601String(),
        ];

        $timeoutSeconds = max(0.05, $this->timeoutMs / 1000);

        try {
            $response = Http::timeout($timeoutSeconds)
                ->connectTimeout($timeoutSeconds)
                ->asJson()
                ->acceptJson()
                ->post(rtrim($this->baseUrl, '/').'/risk/evaluate', $payload);

            if ($response->successful()) {
                $data = $response->json();

                return RiskEvaluationLog::create([
                    'correlation_id' => $correlationId,
                    'user_id' => $user?->id,
                    'device_id' => $device?->id,
                    'event_type' => $eventType,
                    'risk_score' => (int) ($data['risk_score'] ?? 0),
                    'risk_level' => $data['risk_level'] ?? RiskEvaluationLog::LEVEL_LOW,
                    'recommended_action' => $data['recommended_action'] ?? RiskEvaluationLog::ACTION_ALLOW,
                    'enforced_action' => null,
                    'evaluate_reached' => true,
                    'engine_version' => $data['engine_version'] ?? '1.0.0',
                    'reasons_json' => $data['reasons'] ?? $data['reasons_json'] ?? [],
                    'ip_address' => $ip,
                    'evaluated_at' => Carbon::now(),
                ]);
            }

            Log::warning("Risk engine returned HTTP {$response->status()}", ['body' => $response->body()]);
        } catch (Exception $e) {
            // Strict Fail-Open resilience: log warning and proceed safely
            Log::warning('Risk evaluation microservice unreachable (fail-open triggered): '.$e->getMessage(), [
                'correlation_id' => $correlationId,
                'timeout_ms' => $this->timeoutMs,
            ]);
        }

        // Fail-open fallback
        return RiskEvaluationLog::create([
            'correlation_id' => $correlationId,
            'user_id' => $user?->id,
            'device_id' => $device?->id,
            'event_type' => $eventType,
            'risk_score' => 0,
            'risk_level' => RiskEvaluationLog::LEVEL_LOW,
            'recommended_action' => RiskEvaluationLog::ACTION_ALLOW,
            'enforced_action' => null,
            'evaluate_reached' => false,
            'engine_version' => 'fallback-1.0.0',
            'reasons_json' => ['engine_unreachable' => 'Fail-open policy triggered on microservice timeout or error'],
            'ip_address' => $ip,
            'evaluated_at' => Carbon::now(),
        ]);
    }
}
