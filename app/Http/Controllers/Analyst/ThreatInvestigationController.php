<?php

namespace App\Http\Controllers\Analyst;

use App\Http\Controllers\Controller;
use App\Models\RiskEvaluationLog;
use App\Services\AuditLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ThreatInvestigationController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService
    ) {}

    /**
     * Query risk evaluation logs (Anomaly detection results).
     */
    public function riskLogs(Request $request): JsonResponse
    {
        $query = RiskEvaluationLog::query()
            ->with(['user:id,username,email,type', 'device:id,device_identifier,device_name,is_trusted,is_blocked']);

        if ($request->filled('risk_level')) {
            $query->where('risk_level', $request->input('risk_level'));
        }

        if ($request->filled('recommended_action')) {
            $query->where('recommended_action', $request->input('recommended_action'));
        }

        if ($request->filled('min_risk_score')) {
            $query->where('risk_score', '>=', $request->integer('min_risk_score'));
        }

        if ($request->boolean('unresolved_only')) {
            $query->unresolved();
        }

        $logs = $query->latest('evaluated_at')->paginate($request->integer('per_page', 25));

        return response()->json([
            'status' => 'success',
            'data' => $logs,
        ]);
    }

    /**
     * Get detailed anomaly investigation data for a single log.
     */
    public function anomalyDetails(RiskEvaluationLog $riskLog): JsonResponse
    {
        $riskLog->load([
            'user',
            'device.sightings' => fn ($q) => $q->latest('sighted_at')->take(5),
            'responseActions',
        ]);

        return response()->json([
            'status' => 'success',
            'data' => $riskLog,
        ]);
    }

    /**
     * Acknowledge/resolve an anomaly alert.
     */
    public function acknowledgeAlert(Request $request, RiskEvaluationLog $riskLog): JsonResponse
    {
        $action = $request->input('enforced_action', 'ACKNOWLEDGED_BY_ANALYST');
        $riskLog->update(['enforced_action' => $action]);

        $this->auditLogService->recordFromRequest(
            $request,
            'THREAT_RESPONSE',
            'ALERT_ACKNOWLEDGED',
            "Anomaly alert {$riskLog->correlation_id} acknowledged: {$action}",
            ['risk_log_id' => $riskLog->id, 'action' => $action]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Anomaly alert acknowledged successfully.',
            'data' => $riskLog->fresh(),
        ]);
    }
}
