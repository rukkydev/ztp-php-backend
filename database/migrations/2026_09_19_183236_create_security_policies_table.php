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
        Schema::create('security_policies', function (Blueprint $table) {
            $table->id();
            $table->string('policy_name');
            $table->text('description')->nullable();
            $table->string('rule_type'); // MAX_FAILED_LOGINS, GEO_VELOCITY, UNTRUSTED_DEVICE_SCORE_THRESHOLD, IP_REPUTATION, etc.
            $table->string('threshold_value');
            $table->string('action_on_breach'); // BLOCK_DEVICE, LOCK_ACCOUNT, MFA_CHALLENGE, FORCE_MFA, etc.
            $table->boolean('is_enabled')->default(true);
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index('rule_type');
            $table->index('is_enabled');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_policies');
    }
};
