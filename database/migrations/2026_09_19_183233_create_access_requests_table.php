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
        Schema::create('access_requests', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
            $table->foreignId('device_id')->nullable()->constrained('devices')->nullOnDelete();
            $table->string('resource_name');
            $table->string('action_requested');
            $table->string('status')->default('PENDING'); // PENDING, GRANTED, DENIED, CHALLENGED
            $table->string('ip_address', 45)->nullable();
            $table->unsignedInteger('evaluated_risk_score')->default(0);
            $table->timestamps();

            $table->index('status');
            $table->index('resource_name');
            $table->index(['user_id', 'status']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('access_requests');
    }
};
