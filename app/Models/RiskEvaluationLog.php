<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class RiskEvaluationLog extends Model
{
    use HasFactory;

    public const LEVEL_LOW = 'LOW';

    public const LEVEL_MEDIUM = 'MEDIUM';

    public const LEVEL_HIGH = 'HIGH';

    public const LEVEL_CRITICAL = 'CRITICAL';

    public const ACTION_ALLOW = 'ALLOW';

    public const ACTION_MFA_CHALLENGE = 'MFA_CHALLENGE';

    public const ACTION_RESTRICT = 'RESTRICT';

    public const ACTION_BLOCK = 'BLOCK';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'correlation_id',
        'user_id',
        'device_id',
        'event_type',
        'risk_score',
        'risk_level',
        'recommended_action',
        'enforced_action',
        'evaluate_reached',
        'engine_version',
        'reasons_json',
        'ip_address',
        'evaluated_at',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'risk_score' => 'integer',
            'evaluate_reached' => 'boolean',
            'reasons_json' => 'array',
            'evaluated_at' => 'datetime',
        ];
    }

    // ==========================================
    // Relationships
    // ==========================================

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function device(): BelongsTo
    {
        return $this->belongsTo(Device::class);
    }

    public function responseActions(): HasMany
    {
        return $this->hasMany(ResponseAction::class, 'triggered_by_risk_log_id');
    }

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopeHighRisk(Builder $query, int $threshold = 70): Builder
    {
        return $query->where('risk_score', '>=', $threshold);
    }

    public function scopeCritical(Builder $query): Builder
    {
        return $query->where('risk_level', self::LEVEL_CRITICAL);
    }

    public function scopeByLevel(Builder $query, string $level): Builder
    {
        return $query->where('risk_level', $level);
    }

    public function scopeByType(Builder $query, string $type): Builder
    {
        return $query->where('event_type', $type);
    }

    public function scopeInLastMinutes(Builder $query, int $minutes = 60): Builder
    {
        return $query->where('evaluated_at', '>=', Carbon::now()->subMinutes($minutes));
    }

    public function scopeUnresolved(Builder $query): Builder
    {
        return $query->whereIn('risk_level', [self::LEVEL_HIGH, self::LEVEL_CRITICAL])
            ->whereNull('enforced_action');
    }
}
