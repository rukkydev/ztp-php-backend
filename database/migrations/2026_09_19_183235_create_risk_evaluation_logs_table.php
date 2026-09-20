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
        Schema::create('risk_evaluation_logs', function (Blueprint $table) {
            $table->id();
            $table->uuid('correlation_id')->index();
            $table->foreignId('user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('device_id')->nullable()->constrained('devices')->nullOnDelete();
            $table->string('event_type')->nullable();
            $table->unsignedInteger('risk_score')->default(0);
            $table->string('risk_level')->default('LOW'); // LOW, MEDIUM, HIGH, CRITICAL
            $table->string('recommended_action')->default('ALLOW'); // ALLOW, MFA_CHALLENGE, RESTRICT, BLOCK
            $table->string('enforced_action')->nullable();
            $table->boolean('evaluate_reached')->default(true);
            $table->string('engine_version')->default('1.0.0');
            $table->json('reasons_json')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->timestamp('evaluated_at')->useCurrent()->index();
            $table->timestamps();

            $table->index('risk_level');
            $table->index('recommended_action');
            $table->index(['user_id', 'evaluated_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('risk_evaluation_logs');
    }
};
