<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Device extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'device_identifier',
        'device_name',
        'device_type',
        'browser',
        'operating_system',
        'ip_address',
        'is_trusted',
        'is_blocked',
        'last_seen_at',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_trusted' => 'boolean',
            'is_blocked' => 'boolean',
            'last_seen_at' => 'datetime',
        ];
    }

    // ==========================================
    // Relationships
    // ==========================================

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function sightings(): HasMany
    {
        return $this->hasMany(DeviceSighting::class);
    }

    public function accessRequests(): HasMany
    {
        return $this->hasMany(AccessRequest::class);
    }

    public function networkEvents(): HasMany
    {
        return $this->hasMany(NetworkEvent::class);
    }

    public function riskLogs(): HasMany
    {
        return $this->hasMany(RiskEvaluationLog::class);
    }

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopeTrusted(Builder $query): Builder
    {
        return $query->where('is_trusted', true);
    }

    public function scopeBlocked(Builder $query): Builder
    {
        return $query->where('is_blocked', true);
    }

    public function scopeUnblocked(Builder $query): Builder
    {
        return $query->where('is_blocked', false);
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_blocked', false)
            ->whereNotNull('last_seen_at');
    }
}
