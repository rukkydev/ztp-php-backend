<?php

use App\Http\Controllers\Admin\AdminDashboardController;
use App\Http\Controllers\Admin\AdminDeviceController;
use App\Http\Controllers\Admin\AdminReportController;
use App\Http\Controllers\Admin\AdminRoleController;
use App\Http\Controllers\Admin\AdminSessionController;
use App\Http\Controllers\Admin\AdminSettingsController;
use App\Http\Controllers\Admin\PolicyController;
use App\Http\Controllers\Admin\SystemConfigController;
use App\Http\Controllers\Admin\UserManagementController;
use App\Http\Controllers\Analyst\NetworkMonitoringController;
use App\Http\Controllers\Analyst\ThreatInvestigationController;
use App\Http\Controllers\Analyst\ThreatResponseController;
use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\PasswordResetController;
use App\Http\Controllers\Auth\RecoveryPhraseController;
use App\Http\Controllers\Security\AuditLogController;
use App\Http\Controllers\Security\CsrfCookieController;
use App\Http\Controllers\User\AccountController;
use App\Http\Controllers\User\DeviceController;
use App\Http\Controllers\User\NotificationController;
use App\Http\Controllers\User\SessionController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes - Zero-Trust Network Monitoring & Threat Prevention
|--------------------------------------------------------------------------
*/

// Public CSRF Bootstrap
Route::get('/csrf-token', [CsrfCookieController::class, 'csrfToken']);

// Public Authentication Endpoints (Requiring Device ID where appropriate)
Route::prefix('auth')->group(function () {
    Route::post('/login', [AuthController::class, 'login'])->middleware('device.required');
    Route::post('/verify-otp', [AuthController::class, 'verifyOtp'])->middleware('device.required');
    Route::post('/verify-device', [AuthController::class, 'verifyDevice'])->middleware('device.required');
    Route::post('/2fa/verify', [AuthController::class, 'verify2fa'])->middleware('device.required');
    Route::post('/resend-otp', [AuthController::class, 'resendOtp']);
    Route::post('/verify-device/resend', [AuthController::class, 'resendDeviceOtp']);
    Route::post('/2fa/resend', [AuthController::class, 'resend2faOtp']);
    Route::post('/forgot-password', [PasswordResetController::class, 'forgotPassword']);
    Route::post('/reset-password', [PasswordResetController::class, 'resetPassword']);
    Route::post('/recover-account', [RecoveryPhraseController::class, 'recoverAccount']);
    Route::post('/recover-with-phrase', [RecoveryPhraseController::class, 'recoverWithPhrase']);
});

// Protected Zero-Trust Authenticated Routes
Route::middleware(['auth:web', 'device.required', 'ztp.verify'])->group(function () {

    // Current Authenticated Session & Context
    Route::prefix('auth')->group(function () {
        Route::get('/me', [AuthController::class, 'me']);
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::post('/recovery-phrase/generate', [RecoveryPhraseController::class, 'generatePhrase']);
    });

    // User Self-Management & Registered Devices
    Route::prefix('user')->group(function () {
        Route::get('/profile', [AccountController::class, 'profile']);
        Route::put('/profile', [AccountController::class, 'updateProfile']);
        Route::post('/change-password', [AccountController::class, 'changePassword']);
        Route::post('/two-factor/toggle', [AccountController::class, 'toggleTwoFactor']);

        Route::get('/devices', [DeviceController::class, 'index']);
        Route::post('/devices/{device}/trust', [DeviceController::class, 'trustDevice']);
        Route::delete('/devices/{device}', [DeviceController::class, 'revokeDevice']);

        Route::get('/sessions', [SessionController::class, 'index']);
        Route::delete('/sessions', [SessionController::class, 'destroyOthers']);
        Route::delete('/sessions/{session}', [SessionController::class, 'destroy']);
    });

    // Security Analyst & Admin Routes (SOC Operations)
    Route::middleware(['user.type:admin,security_analyst'])->group(function () {
        // Network Monitoring
        Route::prefix('analyst/network')->group(function () {
            Route::get('/overview', [NetworkMonitoringController::class, 'networkMonitoringOverview']);
            Route::get('/events', [NetworkMonitoringController::class, 'events']);
            Route::get('/metrics', [NetworkMonitoringController::class, 'metrics']);
            Route::get('/live', [NetworkMonitoringController::class, 'liveTraffic']);
        });

        // Threat Investigation & Anomaly Results
        Route::prefix('analyst/threats')->group(function () {
            Route::get('/overview', [ThreatInvestigationController::class, 'anomalyDetectionOverview']);
            Route::get('/risk-logs', [ThreatInvestigationController::class, 'riskLogs']);
            Route::get('/risk-logs/{riskLog}', [ThreatInvestigationController::class, 'anomalyDetails']);
            Route::post('/risk-logs/{riskLog}/acknowledge', [ThreatInvestigationController::class, 'acknowledgeAlert']);
        });

        // Threat Prevention Response & Overrides
        Route::prefix('analyst/threat-responses')->group(function () {
            Route::get('/actions', [ThreatResponseController::class, 'actions']);
            Route::post('/mitigate', [ThreatResponseController::class, 'manualMitigate']);
            Route::post('/actions/{responseAction}/revert', [ThreatResponseController::class, 'revertAction']);
        });

        Route::post('/analyst/devices/{device}/unblock', [ThreatResponseController::class, 'unblockDevice']);

        // Audit Logs (View & Export)
        Route::prefix('security/audit-logs')->group(function () {
            Route::get('/', [AuditLogController::class, 'index']);
            Route::get('/export', [AuditLogController::class, 'export']);
        });
    });

    // Super Administrator Only Routes
    Route::middleware(['user.type:admin'])->prefix('admin')->group(function () {
        // Admin Dashboard Overview
        Route::get('/dashboard', [AdminDashboardController::class, 'index']);

        // Device Management Across Platform
        Route::get('/devices', [AdminDeviceController::class, 'index']);
        Route::patch('/devices/bulk-block', [AdminDeviceController::class, 'bulkBlock']);
        Route::patch('/devices/{device}', [AdminDeviceController::class, 'updateStatus']);

        // Platform Active Sessions Control
        Route::get('/sessions', [AdminSessionController::class, 'index']);
        Route::delete('/sessions/bulk', [AdminSessionController::class, 'bulkDestroy']);
        Route::delete('/sessions/{session}', [AdminSessionController::class, 'destroy']);

        // Threats and Anomaly Investigations (Admin access)
        Route::get('/threats', [ThreatInvestigationController::class, 'riskLogs']);
        Route::get('/threats/{riskLog}', [ThreatInvestigationController::class, 'anomalyDetails']);
        Route::patch('/threats/bulk-mitigate', [ThreatInvestigationController::class, 'bulkMitigateThreats']);
        Route::patch('/threats/{riskLog}', [ThreatInvestigationController::class, 'mitigateThreat']);

        Route::get('/alerts', [ThreatInvestigationController::class, 'riskLogs']);
        Route::get('/alerts/{riskLog}', [ThreatInvestigationController::class, 'anomalyDetails']);
        Route::patch('/alerts/bulk-resolve', [ThreatInvestigationController::class, 'bulkResolveAlerts']);
        Route::patch('/alerts/{riskLog}', [ThreatInvestigationController::class, 'resolveAlert']);
        Route::post('/alerts/{riskLog}/acknowledge', [ThreatInvestigationController::class, 'acknowledgeAlert']);

        // Network Monitoring & Anomaly Detection Dashboard Views
        Route::get('/network-monitoring', [NetworkMonitoringController::class, 'networkMonitoringOverview']);
        Route::get('/anomaly-detection', [ThreatInvestigationController::class, 'anomalyDetectionOverview']);

        // Activity Logs (Admin access)
        Route::get('/activity-logs', [AuditLogController::class, 'index']);
        Route::get('/activity-logs/{auditLog}', [AuditLogController::class, 'show']);

        // User Provisioning & Control
        Route::apiResource('users', UserManagementController::class);
        Route::post('/users/{user}/lock', [UserManagementController::class, 'lockUser']);
        Route::post('/users/{user}/unlock', [UserManagementController::class, 'unlockUser']);

        // Security Policies Administration
        Route::apiResource('policies', PolicyController::class);
        Route::post('/policies/{policy}/toggle', [PolicyController::class, 'toggle']);

        // Roles and Permissions
        Route::get('/roles', [AdminRoleController::class, 'index']);
        Route::patch('/roles/{id}', [AdminRoleController::class, 'update']);

        // Reports Generation & Download
        Route::get('/reports', [AdminReportController::class, 'index']);
        Route::post('/reports', [AdminReportController::class, 'store']);
        Route::get('/reports/{id}', [AdminReportController::class, 'show']);
        Route::get('/reports/{id}/download', [AdminReportController::class, 'download']);

        // Platform Settings
        Route::get('/settings', [AdminSettingsController::class, 'index']);
        Route::patch('/settings', [AdminSettingsController::class, 'update']);

        // System Configuration
        Route::get('/system/config', [SystemConfigController::class, 'index']);
    });

    // Account Route Aliases (Frontend compatibility)
    Route::prefix('account')->group(function () {
        Route::get('/overview', [AccountController::class, 'overview']);

        Route::get('/profile', [AccountController::class, 'profile']);
        Route::put('/profile', [AccountController::class, 'updateProfile']);
        Route::post('/profile/avatar', [AccountController::class, 'uploadAvatar']);
        Route::post('/change-password', [AccountController::class, 'changePassword']);

        Route::get('/security/recovery-phrase/status', [AccountController::class, 'recoveryPhraseStatus']);
        Route::post('/security/recovery-phrase/generate', [AccountController::class, 'generateRecoveryPhrase']);

        Route::get('/notification-preferences', [AccountController::class, 'notificationPreferences']);
        Route::patch('/notification-preferences', [AccountController::class, 'updateNotificationPreferences']);

        Route::get('/notifications', [NotificationController::class, 'index']);
        Route::get('/notifications/unread-count', [NotificationController::class, 'unreadCount']);
        Route::patch('/notifications/read-all', [NotificationController::class, 'markAllAsRead']);
        Route::patch('/notifications/{id}/read', [NotificationController::class, 'markAsRead']);

        Route::get('/devices', [DeviceController::class, 'index']);
        Route::post('/devices/{device}/trust', [DeviceController::class, 'trustDevice']);
        Route::delete('/devices/{device}', [DeviceController::class, 'revokeDevice']);

        Route::get('/sessions', [SessionController::class, 'index']);
        Route::delete('/sessions', [SessionController::class, 'destroyOthers']);
        Route::delete('/sessions/{session}', [SessionController::class, 'destroy']);
    });
});
