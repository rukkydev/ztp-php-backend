<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\RecoverAccountRequest;
use App\Models\User;
use App\Services\AuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class RecoveryPhraseController extends Controller
{
    public function __construct(
        protected AuthService $authService
    ) {}

    /**
     * Generate emergency recovery phrase for authenticated user.
     */
    public function generatePhrase(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $phrase = $this->authService->generateEmergencyRecoveryPhrase($user);

        return response()->json([
            'status' => 'success',
            'data' => [
                'recovery_phrase' => $phrase,
                'warning' => 'Save this recovery phrase in a secure password vault. It will NOT be shown again.',
            ],
        ]);
    }

    /**
     * Recover account using emergency recovery phrase.
     */
    public function recoverAccount(RecoverAccountRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $this->authService->recoverAccountWithPhrase(
            $validated['username'],
            $validated['recovery_phrase'],
            $validated['password'],
            $request
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Account unlocked and password reset successfully. You may now log in.',
        ]);
    }

    /**
     * Recover account using recovery phrase (Frontend compatible endpoint).
     */
    public function recoverWithPhrase(Request $request): JsonResponse
    {
        $request->validate([
            'email' => ['required_without:username', 'string'],
            'username' => ['required_without:email', 'string'],
            'phrase' => ['required_without:recovery_phrase', 'string'],
            'recovery_phrase' => ['required_without:phrase', 'string'],
            'newPassword' => ['required_without:password', 'string', 'min:8'],
            'password' => ['required_without:newPassword', 'string', 'min:8'],
        ]);

        $identity = $request->input('email') ?? $request->input('username');
        $phrase = $request->input('phrase') ?? $request->input('recovery_phrase');
        $newPassword = $request->input('newPassword') ?? $request->input('password');

        $this->authService->recoverAccountWithPhrase(
            (string) $identity,
            (string) $phrase,
            (string) $newPassword,
            $request
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Account recovered successfully. You may now sign in with your new password.',
        ]);
    }
}
