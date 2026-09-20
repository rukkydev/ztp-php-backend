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
        Schema::create('response_actions', function (Blueprint $table) {
            $table->id();
            $table->uuid('correlation_id')->index();
            $table->string('target_type'); // USER, DEVICE, SESSION, IP
            $table->string('target_identifier');
            $table->string('action_taken'); // BLOCK_DEVICE, LOCK_ACCOUNT, KILL_SESSIONS, FORCE_MFA
            $table->string('status')->default('PENDING'); // PENDING, EXECUTED, REVERTED
            $table->foreignId('triggered_by_risk_log_id')->nullable()->constrained('risk_evaluation_logs')->nullOnDelete();
            $table->timestamp('executed_at')->nullable();
            $table->timestamps();

            $table->index('target_type');
            $table->index('status');
            $table->index('action_taken');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('response_actions');
    }
};
