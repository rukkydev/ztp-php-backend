<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AuditLog extends Model
{
    use HasFactory;

    public const CATEGORY_AUTHENTICATION = 'AUTHENTICATION';

    public const CATEGORY_ACCESS_CONTROL = 'ACCESS_CONTROL';

    public const CATEGORY_POLICY = 'POLICY';

    public const CATEGORY_THREAT_RESPONSE = 'THREAT_RESPONSE';

    public const CATEGORY_DEVICE = 'DEVICE';

    public const CATEGORY_USER_MANAGEMENT = 'USER_MANAGEMENT';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'correlation_id',
        'actor_id',
        'actor_username',
        'actor_type',
        'event_category',
        'action',
        'description',
        'ip_address',
        'metadata_json',
    ];

    /**
     * The accessors to append to the model's array form.
     *
     * @var list<string>
     */
    protected $appends = [
        'actorUsername',
        'eventType',
        'ipAddress',
        'createdAt',
        'correlationId',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'metadata_json' => 'array',
        ];
    }

    public function getActorUsernameAttribute(): string
    {
        return $this->actor_username ?? $this->actor?->username ?? 'System';
    }

    public function getEventTypeAttribute(): string
    {
        return $this->action ?? 'SECURITY_EVENT';
    }

    public function getIpAddressAttribute(): string
    {
        return $this->attributes['ip_address'] ?? '127.0.0.1';
    }

    public function getCreatedAtAttribute(): string
    {
        return ($this->attributes['created_at'] ? Carbon::parse($this->attributes['created_at']) : Carbon::now())->toIso8601String();
    }

    public function getCorrelationIdAttribute(): ?string
    {
        return $this->attributes['correlation_id'] ?? null;
    }

    // ==========================================
    // Relationships
    // ==========================================

    public function actor(): BelongsTo
    {
        return $this->belongsTo(User::class, 'actor_id');
    }

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopeByCategory(Builder $query, string $category): Builder
    {
        return $query->where('event_category', $category);
    }

    public function scopeByAction(Builder $query, string $action): Builder
    {
        return $query->where('action', $action);
    }

    public function scopeByActor(Builder $query, int $actorId): Builder
    {
        return $query->where('actor_id', $actorId);
    }

    public function scopeRecent(Builder $query, int $days = 7): Builder
    {
        return $query->where('created_at', '>=', Carbon::now()->subDays($days));
    }
}
