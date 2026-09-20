<?php

namespace App\Http\Requests\Admin;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

class StorePolicyRequest extends FormRequest
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
            'policy_name' => ['required', 'string', 'max:255'],
            'description' => ['nullable', 'string'],
            'rule_type' => ['required', 'string', 'max:100'],
            'threshold_value' => ['required', 'string', 'max:100'],
            'action_on_breach' => ['required', 'string', 'max:100'],
            'is_enabled' => ['nullable', 'boolean'],
        ];
    }
}
