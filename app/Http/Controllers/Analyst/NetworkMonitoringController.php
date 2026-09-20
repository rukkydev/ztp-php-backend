<?php

namespace App\Http\Controllers\Analyst;

use App\Http\Controllers\Controller;
use App\Models\NetworkEvent;
use App\Services\NetworkMonitoringService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class NetworkMonitoringController extends Controller
{
    public function __construct(
        protected NetworkMonitoringService $monitoringService
    ) {}

    /**
     * Query network traffic events with filters.
     */
    public function events(Request $request): JsonResponse
    {
        $query = NetworkEvent::query()
            ->with(['user:id,username,name,type', 'device:id,device_identifier,device_name,is_trusted,is_blocked']);

        if ($request->filled('event_type')) {
            $query->where('event_type', $request->input('event_type'));
        }

        if ($request->filled('ip_address')) {
            $query->where('ip_address', $request->input('ip_address'));
        }

        if ($request->filled('status_code')) {
            $query->where('status_code', $request->integer('status_code'));
        }

        if ($request->boolean('failed_only')) {
            $query->where('status_code', '>=', 400);
        }

        $events = $query->latest('created_at')->paginate($request->integer('per_page', 50));

        return response()->json([
            'status' => 'success',
            'data' => $events,
        ]);
    }

    /**
     * Aggregated monitoring metrics and charts.
     */
    public function metrics(Request $request): JsonResponse
    {
        $hours = $request->integer('hours', 24);
        $metrics = $this->monitoringService->getMetrics($hours);

        return response()->json([
            'status' => 'success',
            'data' => $metrics,
        ]);
    }

    /**
     * Real-time live traffic stream (last 50 events).
     */
    public function liveTraffic(): JsonResponse
    {
        $events = NetworkEvent::with(['user:id,username', 'device:id,device_name'])
            ->latest('id')
            ->take(50)
            ->get();

        return response()->json([
            'status' => 'success',
            'data' => $events,
        ]);
    }
}
