<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityPolicy extends Model
{
    use HasFactory;

    public const RULE_MAX_FAILED_LOGINS = 'MAX_FAILED_LOGINS';

    public const RULE_GEO_VELOCITY = 'GEO_VELOCITY';

    public const RULE_RISK_SCORE_THRESHOLD = 'RISK_SCORE_THRESHOLD';

    public const RULE_UNTRUSTED_DEVICE_SCORE_THRESHOLD = 'UNTRUSTED_DEVICE_SCORE_THRESHOLD';

    public const RULE_CRITICAL_RISK_SCORE = 'CRITICAL_RISK_SCORE';

    public const ACTION_BLOCK_DEVICE = 'BLOCK_DEVICE';

    public const ACTION_LOCK_ACCOUNT = 'LOCK_ACCOUNT';

    public const ACTION_KILL_SESSIONS = 'KILL_SESSIONS';

    public const ACTION_FORCE_MFA = 'FORCE_MFA';

    public const ACTION_MFA_CHALLENGE = 'MFA_CHALLENGE';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'policy_name',
        'description',
        'rule_type',
        'threshold_value',
        'action_on_breach',
        'is_enabled',
        'created_by',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_enabled' => 'boolean',
        ];
    }

    // ==========================================
    // Relationships
    // ==========================================

    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopeEnabled(Builder $query): Builder
    {
        return $query->where('is_enabled', true);
    }

    public function scopeByType(Builder $query, string $ruleType): Builder
    {
        return $query->where('rule_type', $ruleType);
    }
}
