<?php

namespace App\Http\Requests\Admin;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

class UpdatePolicyRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->isAdmin() ?? false;
    }

    /**
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'policy_name' => ['sometimes', 'string', 'max:255'],
            'description' => ['nullable', 'string'],
            'rule_type' => ['sometimes', 'string', 'max:100'],
            'threshold_value' => ['sometimes', 'string', 'max:100'],
            'action_on_breach' => ['sometimes', 'string', 'max:100'],
            'is_enabled' => ['sometimes', 'boolean'],
        ];
    }
}
