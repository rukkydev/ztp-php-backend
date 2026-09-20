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
