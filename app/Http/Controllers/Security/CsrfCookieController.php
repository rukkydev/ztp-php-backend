<?php

namespace App\Http\Controllers\Security;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class CsrfCookieController extends Controller
{
    /**
     * Bootstrap CSRF token and deliver cookie for SPA.
     */
    public function csrfToken(Request $request): JsonResponse
    {
        return response()->json([
            'status' => 'success',
            'csrf_token' => csrf_token(),
            'message' => 'CSRF cookie initialized successfully.',
        ]);
    }
}
