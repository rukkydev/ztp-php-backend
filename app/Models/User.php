<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, Notifiable;

    public const TYPE_USER = 'user';

    public const TYPE_SECURITY_ANALYST = 'security_analyst';

    public const TYPE_ADMIN = 'admin';

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'username',
        'name',
        'email',
        'password',
        'type',
        'department',
        'job_title',
        'avatar_url',
        'is_active',
        'two_factor_enabled',
        'two_factor_secret',
        'recovery_phrase_hash',
        'failed_login_attempts',
        'account_locked',
        'locked_until',
        'last_login_at',
    ];

    /**
     * The accessors to append to the model's array form.
     *
     * @var list<string>
     */
    protected $appends = [
        'role',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'recovery_phrase_hash',
    ];

    /**
     * Get the role attribute for frontend role-based access control.
     */
    public function getRoleAttribute(): string
    {
        return $this->type ?? self::TYPE_USER;
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            'is_active' => 'boolean',
            'two_factor_enabled' => 'boolean',
            'account_locked' => 'boolean',
            'locked_until' => 'datetime',
            'last_login_at' => 'datetime',
            'failed_login_attempts' => 'integer',
        ];
    }

    /**
     * Email attribute mutator for normalization.
     */
    protected function email(): Attribute
    {
        return Attribute::make(
            set: fn (?string $value) => $value ? strtolower(trim($value)) : null,
        );
    }

    /**
     * Username attribute mutator for normalization.
     */
    protected function username(): Attribute
    {
        return Attribute::make(
            set: fn (?string $value) => $value ? strtolower(trim($value)) : null,
        );
    }

    // ==========================================
    // Relationships
    // ==========================================

    public function devices(): HasMany
    {
        return $this->hasMany(Device::class);
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

    public function auditLogs(): HasMany
    {
        return $this->hasMany(AuditLog::class, 'actor_id');
    }

    public function oneTimeCodes(): HasMany
    {
        return $this->hasMany(OneTimeCode::class);
    }

    public function passwordResetTokens(): HasMany
    {
        return $this->hasMany(PasswordResetToken::class);
    }

    public function createdPolicies(): HasMany
    {
        return $this->hasMany(SecurityPolicy::class, 'created_by');
    }

    // ==========================================
    // Query Scopes
    // ==========================================

    public function scopeActive(Builder $query): Builder
    {
        return $query->where('is_active', true);
    }

    public function scopeLocked(Builder $query): Builder
    {
        return $query->where('account_locked', true);
    }

    public function scopeUnlocked(Builder $query): Builder
    {
        return $query->where('account_locked', false);
    }

    public function scopeByType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }

    public function scopeAdmins(Builder $query): Builder
    {
        return $query->where('type', self::TYPE_ADMIN);
    }

    public function scopeAnalysts(Builder $query): Builder
    {
        return $query->where('type', self::TYPE_SECURITY_ANALYST);
    }

    public function scopeStandardUsers(Builder $query): Builder
    {
        return $query->where('type', self::TYPE_USER);
    }

    // ==========================================
    // Helper Methods & Role Checks
    // ==========================================

    public function isAdmin(): bool
    {
        return $this->type === self::TYPE_ADMIN;
    }

    public function isSecurityAnalyst(): bool
    {
        return $this->type === self::TYPE_SECURITY_ANALYST;
    }

    public function isStandardUser(): bool
    {
        return $this->type === self::TYPE_USER;
    }

    public function isLocked(): bool
    {
        if (! $this->account_locked) {
            return false;
        }

        if ($this->locked_until && $this->locked_until->isPast()) {
            return false;
        }

        return true;
    }
}
