<?php

namespace App\Policies;

use App\Models\SecurityPolicy;
use App\Models\User;

class SecurityPolicyPolicy
{
    /**
     * Determine whether the user can view any policies.
     */
    public function viewAny(User $user): bool
    {
        return $user->isAdmin() || $user->isSecurityAnalyst();
    }

    /**
     * Determine whether the user can view the policy.
     */
    public function view(User $user, SecurityPolicy $securityPolicy): bool
    {
        return $user->isAdmin() || $user->isSecurityAnalyst();
    }

    /**
     * Determine whether the user can create policies.
     */
    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    /**
     * Determine whether the user can update the policy.
     */
    public function update(User $user, SecurityPolicy $securityPolicy): bool
    {
        return $user->isAdmin();
    }

    /**
     * Determine whether the user can delete the policy.
     */
    public function delete(User $user, SecurityPolicy $securityPolicy): bool
    {
        return $user->isAdmin();
    }

    /**
     * Determine whether the user can toggle the policy state.
     */
    public function toggle(User $user, SecurityPolicy $securityPolicy): bool
    {
        return $user->isAdmin();
    }
}
