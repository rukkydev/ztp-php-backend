<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\SecurityPolicy;
use App\Services\AuditLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class AdminSettingsController extends Controller
{
    protected const CACHE_KEY = 'ztp_platform_settings';

    public function __construct(
        protected AuditLogService $auditLogService
    ) {}

    /**
     * Get platform settings.
     */
    public function index(): JsonResponse
    {
        $settings = Cache::get(self::CACHE_KEY, function () {
            // Check baseline policies in database
            $require2faPolicy = SecurityPolicy::where('rule_type', SecurityPolicy::RULE_UNTRUSTED_DEVICE_SCORE_THRESHOLD)->first();
            $travelPolicy = SecurityPolicy::where('rule_type', SecurityPolicy::RULE_GEO_VELOCITY)->first();

            return [
                'general' => [
                    'orgName' => 'Zero-Trust Security Operations',
                    'supportEmail' => 'security-ops@ztp.local',
                ],
                'security' => [
                    'sessionTimeout' => (string) config('session.lifetime', 120),
                    'toggles' => [
                        [
                            'id' => 'require-2fa',
                            'label' => 'Require two-factor authentication for all users',
                            'description' => 'New sign-ins will be prompted to set up 2FA if they haven\'t already.',
                            'checked' => $require2faPolicy ? $require2faPolicy->is_enabled : true,
                        ],
                        [
                            'id' => 'enforce-password-rotation',
                            'label' => 'Enforce password rotation every 90 days',
                            'description' => 'Users will be required to set a new password after 90 days.',
                            'checked' => true,
                        ],
                        [
                            'id' => 'alert-impossible-travel',
                            'label' => 'Alert on impossible-travel logins',
                            'description' => 'Flag sign-ins from locations that are geographically implausible given the previous login.',
                            'checked' => $travelPolicy ? $travelPolicy->is_enabled : true,
                        ],
                        [
                            'id' => 'block-legacy-auth',
                            'label' => 'Block legacy authentication protocols',
                            'description' => 'Prevents sign-in methods that don\'t support modern verification.',
                            'checked' => false,
                        ],
                    ],
                ],
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => $settings,
        ]);
    }

    /**
     * Update platform settings.
     */
    public function update(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'general.orgName' => ['nullable', 'string', 'max:255'],
            'general.supportEmail' => ['nullable', 'email', 'max:255'],
            'security.sessionTimeout' => ['nullable', 'string'],
            'security.toggles' => ['nullable', 'array'],
        ]);

        $current = Cache::get(self::CACHE_KEY, [
            'general' => [
                'orgName' => 'Zero-Trust Security Operations',
                'supportEmail' => 'security-ops@ztp.local',
            ],
            'security' => [
                'sessionTimeout' => '120',
                'toggles' => [],
            ],
        ]);

        if (isset($validated['general'])) {
            $current['general'] = array_merge($current['general'], $validated['general']);
        }

        if (isset($validated['security'])) {
            if (isset($validated['security']['sessionTimeout'])) {
                $current['security']['sessionTimeout'] = $validated['security']['sessionTimeout'];
            }
            if (isset($validated['security']['toggles'])) {
                $current['security']['toggles'] = $validated['security']['toggles'];

                // Synchronize relevant SecurityPolicy rows
                foreach ($validated['security']['toggles'] as $toggle) {
                    $key = $toggle['id'] ?? $toggle['key'] ?? null;
                    $checked = $toggle['checked'] ?? $toggle['enabled'] ?? false;
                    if ($key === 'alert-impossible-travel') {
                        SecurityPolicy::where('rule_type', SecurityPolicy::RULE_GEO_VELOCITY)
                            ->update(['is_enabled' => (bool) $checked]);
                    }
                }
            }
        }

        Cache::put(self::CACHE_KEY, $current);

        $this->auditLogService->recordFromRequest(
            $request,
            'PLATFORM_SETTINGS',
            'SETTINGS_UPDATED',
            'Platform general and security settings updated',
            $validated
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Settings updated successfully.',
            'data' => $current,
        ]);
    }
}
