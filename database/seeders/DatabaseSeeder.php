<?php

namespace Database\Seeders;

use App\Models\SecurityPolicy;
use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // 1. Initial Super Administrator
        $admin = User::firstOrCreate(
            ['email' => 'admin@ztp.local'],
            [
                'username' => 'admin',
                'name' => 'System Administrator',
                'password' => 'AdminPassword123!',
                'type' => User::TYPE_ADMIN,
                'department' => 'Information Security',
                'job_title' => 'Chief Information Security Officer',
                'is_active' => true,
                'two_factor_enabled' => false,
            ]
        );

        // 2. Security Analyst
        $analyst = User::firstOrCreate(
            ['email' => 'analyst@ztp.local'],
            [
                'username' => 'analyst',
                'name' => 'Security Operations Analyst',
                'password' => 'AnalystPassword123!',
                'type' => User::TYPE_SECURITY_ANALYST,
                'department' => 'SOC Operations',
                'job_title' => 'Senior SOC Analyst',
                'is_active' => true,
                'two_factor_enabled' => false,
            ]
        );

        // 3. Standard User
        $user = User::firstOrCreate(
            ['email' => 'user@ztp.local'],
            [
                'username' => 'johndoe',
                'name' => 'John Doe',
                'password' => 'UserPassword123!',
                'type' => User::TYPE_USER,
                'department' => 'Engineering',
                'job_title' => 'Software Engineer',
                'is_active' => true,
                'two_factor_enabled' => false,
            ]
        );

        // 4. Baseline Zero-Trust Security Policies
        $policies = [
            [
                'policy_name' => 'Max Failed Login Attempts Lockout',
                'description' => 'Locks user account after 5 consecutive failed login attempts to prevent brute-force attacks.',
                'rule_type' => SecurityPolicy::RULE_MAX_FAILED_LOGINS,
                'threshold_value' => '5',
                'action_on_breach' => SecurityPolicy::ACTION_LOCK_ACCOUNT,
                'is_enabled' => true,
                'created_by' => $admin->id,
            ],
            [
                'policy_name' => 'Geo-Velocity Impossible Travel Detection',
                'description' => 'Challenges user with MFA when access is requested from geographically disparate locations in an impossible timeframe.',
                'rule_type' => SecurityPolicy::RULE_GEO_VELOCITY,
                'threshold_value' => '800',
                'action_on_breach' => SecurityPolicy::ACTION_MFA_CHALLENGE,
                'is_enabled' => true,
                'created_by' => $admin->id,
            ],
            [
                'policy_name' => 'High Risk Score Device Containment',
                'description' => 'Automatically isolates and blocks devices reaching or exceeding risk score of 80.',
                'rule_type' => SecurityPolicy::RULE_RISK_SCORE_THRESHOLD,
                'threshold_value' => '80',
                'action_on_breach' => SecurityPolicy::ACTION_BLOCK_DEVICE,
                'is_enabled' => true,
                'created_by' => $admin->id,
            ],
            [
                'policy_name' => 'Untrusted Device Stepped-Up Verification',
                'description' => 'Requires multi-factor authentication when accessing sensitive resources from untrusted devices.',
                'rule_type' => SecurityPolicy::RULE_UNTRUSTED_DEVICE_SCORE_THRESHOLD,
                'threshold_value' => '60',
                'action_on_breach' => SecurityPolicy::ACTION_MFA_CHALLENGE,
                'is_enabled' => true,
                'created_by' => $admin->id,
            ],
            [
                'policy_name' => 'Critical Threat Session Invalidation',
                'description' => 'Instantly terminates active sessions across all devices when critical malicious anomaly is detected.',
                'rule_type' => SecurityPolicy::RULE_CRITICAL_RISK_SCORE,
                'threshold_value' => '90',
                'action_on_breach' => SecurityPolicy::ACTION_KILL_SESSIONS,
                'is_enabled' => true,
                'created_by' => $admin->id,
            ],
        ];

        foreach ($policies as $policyData) {
            SecurityPolicy::firstOrCreate(
                ['rule_type' => $policyData['rule_type']],
                $policyData
            );
        }
    }
}
