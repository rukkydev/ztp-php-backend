<?php

namespace App\Events;

use App\Models\ResponseAction;
use App\Models\RiskEvaluationLog;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ThreatMitigationTriggered
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public ResponseAction $responseAction,
        public ?RiskEvaluationLog $riskLog = null
    ) {}
}
