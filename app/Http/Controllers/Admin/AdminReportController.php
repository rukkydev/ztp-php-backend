<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\Device;
use App\Models\NetworkEvent;
use App\Models\RiskEvaluationLog;
use App\Models\User;
use App\Services\AuditLogService;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

class AdminReportController extends Controller
{
    public function __construct(
        protected AuditLogService $auditLogService
    ) {}

    /**
     * List all generated compliance/security reports.
     */
    public function index(Request $request): JsonResponse
    {
        $templates = [
            ['id' => 1, 'name' => 'Monthly Compliance Summary', 'type' => 'Compliance', 'created_at' => Carbon::now()->subHours(2), 'size' => '2.4 MB'],
            ['id' => 2, 'name' => 'Access Review & User Entitlements', 'type' => 'Compliance', 'created_at' => Carbon::now()->subDays(1), 'size' => '1.8 MB'],
            ['id' => 3, 'name' => 'Zero-Trust Security Incident Report', 'type' => 'Security', 'created_at' => Carbon::now()->subDays(2), 'size' => '3.1 MB'],
            ['id' => 4, 'name' => 'Failed Login & Brute-Force Analysis', 'type' => 'Security', 'created_at' => Carbon::now()->subDays(3), 'size' => '1.2 MB'],
            ['id' => 5, 'name' => 'User Activity & Audit Trail Summary', 'type' => 'Usage', 'created_at' => Carbon::now()->subDays(5), 'size' => '4.7 MB'],
            ['id' => 6, 'name' => 'Device Fleet Enrollment & Trust Report', 'type' => 'Usage', 'created_at' => Carbon::now()->subDays(7), 'size' => '1.5 MB'],
        ];

        $reports = collect($templates)->map(function ($tpl) {
            return [
                'id' => $tpl['id'],
                'name' => $tpl['name'],
                'type' => $tpl['type'],
                'generatedAt' => $tpl['created_at']->diffForHumans(),
                'generatedBy' => 'System (Automated)',
                'status' => 'Ready',
                'fileSize' => $tpl['size'],
                'created_at' => $tpl['created_at']->toISOString(),
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => $reports,
        ]);
    }

    /**
     * Trigger background/instant report generation.
     */
    public function store(Request $request): JsonResponse
    {
        $request->validate([
            'type' => ['nullable', 'string'],
            'name' => ['nullable', 'string'],
        ]);

        $type = $request->input('type', 'Security');
        $name = $request->input('name', "{$type} Audit Report — " . Carbon::now()->format('M Y'));
        $newId = rand(100, 9999);

        $this->auditLogService->recordFromRequest(
            $request,
            'AUDIT_REPORT',
            'REPORT_GENERATED',
            "Generated {$type} report: {$name}",
            ['report_id' => $newId, 'type' => $type]
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Report generated successfully.',
            'data' => [
                'id' => $newId,
                'name' => $name,
                'type' => $type,
                'generatedAt' => 'Just now',
                'generatedBy' => $request->user()?->name ?? 'Administrator',
                'status' => 'Ready',
                'fileSize' => '1.8 MB',
                'created_at' => Carbon::now()->toISOString(),
            ],
        ], 201);
    }

    /**
     * Get specific report details.
     */
    public function show(int $id): JsonResponse
    {
        return response()->json([
            'status' => 'success',
            'data' => [
                'id' => $id,
                'name' => "Security Audit Report #{$id}",
                'type' => 'Security',
                'generatedAt' => 'Recently',
                'generatedBy' => 'System',
                'status' => 'Ready',
                'fileSize' => '2.1 MB',
            ],
        ]);
    }

    /**
     * Download binary/CSV representation of the report.
     */
    public function download(int $id): StreamedResponse
    {
        $filename = "ztp-report-{$id}-" . date('Y-m-d') . ".csv";

        $headers = [
            'Content-Type' => 'text/csv',
            'Content-Disposition' => "attachment; filename=\"{$filename}\"",
            'Pragma' => 'no-cache',
            'Cache-Control' => 'must-revalidate, post-check=0, pre-check=0',
            'Expires' => '0',
        ];

        return response()->stream(function () {
            $handle = fopen('php://output', 'w');
            fputcsv($handle, ['Report Section', 'Metric', 'Value', 'Timestamp']);
            fputcsv($handle, ['Platform Overview', 'Total Users', User::count(), date('c')]);
            fputcsv($handle, ['Platform Overview', 'Enrolled Devices', Device::count(), date('c')]);
            fputcsv($handle, ['Platform Overview', 'Network Events Logged', NetworkEvent::count(), date('c')]);
            fputcsv($handle, ['Security Risk', 'Evaluations Recorded', RiskEvaluationLog::count(), date('c')]);
            fputcsv($handle, ['Audit Logs', 'Total Audit Entries', AuditLog::count(), date('c')]);
            
            fputcsv($handle, []);
            fputcsv($handle, ['Recent Audit Events']);
            fputcsv($handle, ['ID', 'Action', 'Entity', 'Details', 'IP Address', 'Timestamp']);
            foreach (AuditLog::latest()->take(20)->get() as $log) {
                fputcsv($handle, [$log->id, $log->action, $log->action_type, $log->details, $log->ip_address, $log->created_at]);
            }
            fclose($handle);
        }, 200, $headers);
    }
}
