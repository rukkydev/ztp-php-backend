<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AccessRequest extends Model
{
    use HasFactory;

    public const STATUS_PENDING = 'PENDING';

    public const STATUS_GRANTED = 'GRANTED';

    public const STATUS_DENIED = 'DENIED';

    public const STATUS_CHALLENGED = 'CHALLENGED';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'device_id',
        'resource_name',
        'action_requested',
        'status',
        'ip_address',
        'evaluated_risk_score',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'evaluated_risk_score' => 'integer',
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

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopePending(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_PENDING);
    }

    public function scopeGranted(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_GRANTED);
    }

    public function scopeDenied(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_DENIED);
    }

    public function scopeChallenged(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_CHALLENGED);
    }

    public function scopeHighRisk(Builder $query, int $threshold = 70): Builder
    {
        return $query->where('evaluated_risk_score', '>=', $threshold);
    }
}
