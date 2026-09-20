<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ResponseAction extends Model
{
    use HasFactory;

    public const TARGET_USER = 'USER';

    public const TARGET_DEVICE = 'DEVICE';

    public const TARGET_SESSION = 'SESSION';

    public const TARGET_IP = 'IP';

    public const ACTION_BLOCK_DEVICE = 'BLOCK_DEVICE';

    public const ACTION_LOCK_ACCOUNT = 'LOCK_ACCOUNT';

    public const ACTION_KILL_SESSIONS = 'KILL_SESSIONS';

    public const ACTION_FORCE_MFA = 'FORCE_MFA';

    public const STATUS_PENDING = 'PENDING';

    public const STATUS_EXECUTED = 'EXECUTED';

    public const STATUS_REVERTED = 'REVERTED';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'correlation_id',
        'target_type',
        'target_identifier',
        'action_taken',
        'status',
        'triggered_by_risk_log_id',
        'executed_at',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'executed_at' => 'datetime',
        ];
    }

    // ==========================================
    // Relationships
    // ==========================================

    public function riskLog(): BelongsTo
    {
        return $this->belongsTo(RiskEvaluationLog::class, 'triggered_by_risk_log_id');
    }

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopeExecuted(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_EXECUTED);
    }

    public function scopePending(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_PENDING);
    }

    public function scopeReverted(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_REVERTED);
    }

    public function scopeByTarget(Builder $query, string $type, ?string $identifier = null): Builder
    {
        $q = $query->where('target_type', $type);
        if ($identifier) {
            $q->where('target_identifier', $identifier);
        }

        return $q;
    }

    public function scopeByAction(Builder $query, string $action): Builder
    {
        return $query->where('action_taken', $action);
    }
}
