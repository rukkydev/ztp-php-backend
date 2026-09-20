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
        Schema::create('one_time_codes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->string('code_hash');
            $table->string('purpose')->index(); // LOGIN_2FA, PASSWORD_RESET, EMERGENCY_RECOVERY
            $table->boolean('consumed')->default(false);
            $table->timestamp('expires_at')->index();
            $table->timestamps();

            $table->index(['user_id', 'purpose', 'consumed']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('one_time_codes');
    }
};
