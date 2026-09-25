<?php

use App\Services\RiskEvaluationClient;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Str;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Artisan::command('risk:probe {--test-eval : Perform a test risk evaluation call}', function (RiskEvaluationClient $client) {
    $this->info('--- Zero-Trust Risk Evaluation Engine Health Check ---');

    $health = $client->health();
    $engine = $health['service'] ?? 'unknown';
    $version = $health['version'] ?? 'unknown';
    $healthStatus = $health['status'] ?? 'unreachable';
    $healthColor = $healthStatus === 'ok' ? 'info' : 'error';
    $this->line("Health Probe:  <{$healthColor}>[{$healthStatus}]</{$healthColor}> (Engine: {$engine}, Version: {$version})");

    $ready = $client->ready();
    $readyStatus = $ready['status'] ?? 'unreachable';
    $readyColor = $readyStatus === 'ready' ? 'info' : 'error';
    $modelLoaded = ($ready['model_loaded'] ?? false) ? 'YES' : 'NO';
    $this->line("Ready Probe:   <{$readyColor}>[{$readyStatus}]</{$readyColor}> (Model Loaded: {$modelLoaded})");

    if ($this->option('test-eval') || $healthStatus === 'ok') {
        $this->newLine();
        $this->info('--- Test Risk Evaluation (Sample High-Risk Login) ---');

        $result = $client->evaluateRaw([
            'correlation_id' => (string) Str::uuid(),
            'user_id' => 1,
            'username' => 'probe_user',
            'user_type' => 'user',
            'is_device_trusted' => false,
            'ip_address' => '198.51.100.45',
            'event_type' => 'LOGIN_ATTEMPT',
            'context' => [
                'failed_attempts' => 2,
                'velocity_kmh' => 120.0,
            ],
        ]);

        $this->table(
            ['Field', 'Value'],
            [
                ['Correlation ID', $result['correlation_id']],
                ['Risk Score', $result['risk_score']],
                ['Risk Level', $result['risk_level']],
                ['Recommended Action', $result['recommended_action']],
                ['Reasons', implode(', ', (array) ($result['reasons'] ?? []))],
                ['Engine Version', $result['engine_version']],
                ['Evaluate Reached', $result['evaluate_reached'] ? 'true' : 'false'],
                ['Latency (ms)', $result['latency_ms'] ?? 'N/A'],
            ]
        );
    }
})->purpose('Probe the Zero-Trust Risk Evaluation microservice health, readiness, and latency');
