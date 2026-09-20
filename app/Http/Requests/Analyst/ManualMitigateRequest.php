<?php

namespace App\Http\Requests\Analyst;

use App\Models\ResponseAction;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class ManualMitigateRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->isAdmin() || $this->user()?->isSecurityAnalyst();
    }

    /**
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'target_type' => ['required', Rule::in([ResponseAction::TARGET_USER, ResponseAction::TARGET_DEVICE, ResponseAction::TARGET_SESSION, ResponseAction::TARGET_IP])],
            'target_identifier' => ['required', 'string'],
            'action' => ['required', Rule::in([ResponseAction::ACTION_BLOCK_DEVICE, ResponseAction::ACTION_LOCK_ACCOUNT, ResponseAction::ACTION_KILL_SESSIONS, ResponseAction::ACTION_FORCE_MFA])],
            'reason' => ['nullable', 'string', 'max:500'],
        ];
    }
}
