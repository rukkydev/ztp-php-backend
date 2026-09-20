<?php

namespace App\Services;

use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\Request;

class AuditLogService
{
    /**
     * Record a structured immutable audit log.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function record(
        ?int $actorId,
        ?string $username,
        ?string $type,
        string $category,
        string $action,
        ?string $description = null,
        ?string $ip = null,
        array $metadata = []
    ): AuditLog {
        return AuditLog::create([
            'actor_id' => $actorId,
            'actor_username' => $username,
            'actor_type' => $type ?? 'system',
            'event_category' => $category,
            'action' => $action,
            'description' => $description,
            'ip_address' => $ip,
            'metadata_json' => $metadata,
        ]);
    }

    /**
     * Record audit log from active Request and User.
     *
     * @param  array<string, mixed>  $metadata
     */
    public function recordFromRequest(
        Request $request,
        string $category,
        string $action,
        ?string $description = null,
        array $metadata = []
    ): AuditLog {
        /** @var User|null $user */
        $user = $request->user();

        return $this->record(
            $user?->id,
            $user?->username ?? 'anonymous',
            $user?->type ?? 'guest',
            $category,
            $action,
            $description,
            $request->ip(),
            array_merge($metadata, [
                'user_agent' => $request->userAgent(),
                'device_id' => $request->header('X-Device-Id'),
            ])
        );
    }
}
