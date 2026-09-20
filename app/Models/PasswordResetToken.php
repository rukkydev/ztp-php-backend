<?php

namespace App\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PasswordResetToken extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'user_id',
        'token_hash',
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

    // ==========================================
    // Helpers
    // ==========================================

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }
}
