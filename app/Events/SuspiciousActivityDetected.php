<?php

namespace App\Events;

use App\Models\RiskEvaluationLog;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class SuspiciousActivityDetected
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public RiskEvaluationLog $riskLog
    ) {}
}
