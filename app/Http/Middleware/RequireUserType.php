<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireUserType
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     * @param  string  ...$types
     */
    public function handle(Request $request, Closure $next, ...$types): Response
    {
        /** @var User|null $user */
        $user = $request->user();

        if (! $user) {
            return response()->json([
                'status' => 'error',
                'error_code' => 'UNAUTHENTICATED',
                'message' => 'Authentication required to access this resource.',
            ], Response::HTTP_UNAUTHORIZED);
        }

        // Support comma separated strings like "admin,security_analyst"
        $allowedTypes = [];
        foreach ($types as $type) {
            foreach (explode(',', $type) as $singleType) {
                $allowedTypes[] = trim($singleType);
            }
        }

        if (! in_array($user->type, $allowedTypes, true)) {
            return response()->json([
                'status' => 'error',
                'error_code' => 'FORBIDDEN_INSUFFICIENT_ROLE',
                'message' => 'Unauthorized: Insufficient privileges for this operation.',
                'required_roles' => $allowedTypes,
                'current_role' => $user->type,
            ], Response::HTTP_FORBIDDEN);
        }

        return $next($request);
    }
}
