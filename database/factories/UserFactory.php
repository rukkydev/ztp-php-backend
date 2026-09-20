<?php

namespace Database\Factories;

use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

/**
 * @extends Factory<User>
 */
class UserFactory extends Factory
{
    /**
     * The current password being used by the factory.
     */
    protected static ?string $password;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'username' => fake()->unique()->userName(),
            'name' => fake()->name(),
            'email' => fake()->unique()->safeEmail(),
            'email_verified_at' => now(),
            'password' => static::$password ??= Hash::make('password'),
            'type' => User::TYPE_USER,
            'department' => 'Engineering',
            'job_title' => 'Engineer',
            'is_active' => true,
            'two_factor_enabled' => false,
            'failed_login_attempts' => 0,
            'account_locked' => false,
            'remember_token' => Str::random(10),
        ];
    }

    /**
     * Indicate that the user is an admin.
     */
    public function admin(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => User::TYPE_ADMIN,
            'department' => 'Information Security',
            'job_title' => 'Administrator',
        ]);
    }

    /**
     * Indicate that the user is a security analyst.
     */
    public function analyst(): static
    {
        return $this->state(fn (array $attributes) => [
            'type' => User::TYPE_SECURITY_ANALYST,
            'department' => 'SOC Operations',
            'job_title' => 'SOC Analyst',
        ]);
    }

    /**
     * Indicate that the user is locked.
     */
    public function locked(): static
    {
        return $this->state(fn (array $attributes) => [
            'account_locked' => true,
            'locked_until' => now()->addHours(24),
            'failed_login_attempts' => 5,
        ]);
    }

    /**
     * Indicate that the model's email address should be unverified.
     */
    public function unverified(): static
    {
        return $this->state(fn (array $attributes) => [
            'email_verified_at' => null,
        ]);
    }
}
