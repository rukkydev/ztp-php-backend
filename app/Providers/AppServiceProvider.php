<?php

namespace App\Providers;

use App\Models\AuditLog;
use App\Models\ResponseAction;
use App\Models\SecurityPolicy;
use App\Models\User;
use App\Policies\AuditLogPolicy;
use App\Policies\SecurityPolicyPolicy;
use App\Policies\ThreatResponsePolicy;
use App\Policies\UserPolicy;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Gate::policy(User::class, UserPolicy::class);
        Gate::policy(SecurityPolicy::class, SecurityPolicyPolicy::class);
        Gate::policy(ResponseAction::class, ThreatResponsePolicy::class);
        Gate::policy(AuditLog::class, AuditLogPolicy::class);
    }
}
