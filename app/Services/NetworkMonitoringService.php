<?php

namespace App\Services;

use App\Models\Device;
use App\Models\NetworkEvent;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class NetworkMonitoringService
{
    /**
     * Record a network event.
     */
    public function recordEvent(
        Request $request,
        ?User $user = null,
        ?Device $device = null,
        string $eventType = 'API_ACCESS',
        ?int $statusCode = null,
        ?int $responseTimeMs = null
    ): NetworkEvent {
        return NetworkEvent::create([
            'user_id' => $user?->id ?? $request->user()?->id,
            'device_id' => $device?->id,
            'event_type' => $eventType,
            'ip_address' => $request->ip(),
            'endpoint' => $request->path(),
            'http_method' => $request->method(),
            'payload_hash' => $request->getContent() ? hash('sha256', $request->getContent()) : null,
            'status_code' => $statusCode,
            'response_time_ms' => $responseTimeMs,
        ]);
    }

    /**
     * Retrieve aggregated monitoring metrics.
     *
     * @return array<string, mixed>
     */
    public function getMetrics(int $hours = 24): array
    {
        $since = Carbon::now()->subHours($hours);

        $totalEvents = NetworkEvent::where('created_at', '>=', $since)->count();
        $failedRequests = NetworkEvent::where('created_at', '>=', $since)->where('status_code', '>=', 400)->count();
        $avgResponseTime = (int) NetworkEvent::where('created_at', '>=', $since)->avg('response_time_ms');
        $uniqueIps = NetworkEvent::where('created_at', '>=', $since)->distinct('ip_address')->count('ip_address');

        $eventsByType = NetworkEvent::where('created_at', '>=', $since)
            ->select('event_type', DB::raw('count(*) as count'))
            ->groupBy('event_type')
            ->pluck('count', 'event_type')
            ->toArray();

        $riskSummary = RiskEvaluationLog::where('evaluated_at', '>=', $since)
            ->select('risk_level', DB::raw('count(*) as count'))
            ->groupBy('risk_level')
            ->pluck('count', 'risk_level')
            ->toArray();

        return [
            'period_hours' => $hours,
            'total_events' => $totalEvents,
            'failed_requests' => $failedRequests,
            'average_response_time_ms' => $avgResponseTime,
            'unique_ips_count' => $uniqueIps,
            'events_by_type' => $eventsByType,
            'risk_level_distribution' => $riskSummary,
        ];
    }
}
