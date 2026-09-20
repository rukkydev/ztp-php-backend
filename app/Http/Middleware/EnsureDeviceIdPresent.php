<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureDeviceIdPresent
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $deviceId = $request->header('X-Device-Id');

        if (empty($deviceId)) {
            return response()->json([
                'status' => 'error',
                'error_code' => 'DEVICE_IDENTIFIER_MISSING',
                'message' => 'Mandatory hardware/browser device identifier missing. Ensure X-Device-Id header is set.',
            ], Response::HTTP_BAD_REQUEST);
        }

        return $next($request);
    }
}
