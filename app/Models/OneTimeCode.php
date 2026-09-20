<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class OneTimeCode extends Model
{
    use HasFactory;

    public const PURPOSE_LOGIN_2FA = 'LOGIN_2FA';

    public const PURPOSE_PASSWORD_RESET = 'PASSWORD_RESET';

    public const PURPOSE_EMERGENCY_RECOVERY = 'EMERGENCY_RECOVERY';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'code_hash',
        'purpose',
        'consumed',
        'expires_at',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'consumed' => 'boolean',
            'expires_at' => 'datetime',
        ];
    }

    // ==========================================
    // Relationships
    // ==========================================

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopeUnconsumed(Builder $query): Builder
    {
        return $query->where('consumed', false);
    }

    public function scopeValid(Builder $query): Builder
    {
        return $query->where('consumed', false)
            ->where('expires_at', '>', Carbon::now());
    }

    public function scopePurpose(Builder $query, string $purpose): Builder
    {
        return $query->where('purpose', $purpose);
    }

    // ==========================================
    // Helpers
    // ==========================================

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }
}
