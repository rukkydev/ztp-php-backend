<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('actor_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('actor_username')->nullable();
            $table->string('actor_type')->nullable(); // user, security_analyst, admin, system
            $table->string('event_category')->index(); // AUTHENTICATION, ACCESS_CONTROL, POLICY, THREAT_RESPONSE, DEVICE, USER_MANAGEMENT
            $table->string('action')->index();
            $table->text('description')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->json('metadata_json')->nullable();
            $table->timestamps();

            $table->index(['event_category', 'created_at']);
            $table->index(['actor_id', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('audit_logs');
    }
};
