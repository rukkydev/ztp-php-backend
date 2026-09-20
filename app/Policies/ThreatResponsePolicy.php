<?php

namespace App\Policies;

use App\Models\ResponseAction;
use App\Models\User;

class ThreatResponsePolicy
{
    /**
     * Determine whether the user can view any response actions.
     */
    public function viewAny(User $user): bool
    {
        return $user->isAdmin() || $user->isSecurityAnalyst();
    }

    /**
     * Determine whether the user can view the response action.
     */
    public function view(User $user, ResponseAction $responseAction): bool
    {
        return $user->isAdmin() || $user->isSecurityAnalyst();
    }

    /**
     * Determine whether the user can trigger manual mitigations.
     */
    public function mitigate(User $user): bool
    {
        return $user->isAdmin() || $user->isSecurityAnalyst();
    }

    /**
     * Determine whether the user can revert a mitigation action.
     */
    public function revert(User $user, ResponseAction $responseAction): bool
    {
        return $user->isAdmin() || $user->isSecurityAnalyst();
    }
}
