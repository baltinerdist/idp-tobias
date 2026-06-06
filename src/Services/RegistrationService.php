<?php
declare(strict_types=1);

namespace Amtgard\IdP\Services;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Persistence\Client\Entities\UserEntity;
use Amtgard\IdP\Persistence\Client\Entities\UserLoginEntity;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;

/**
 * Shared registration flow used by AuthController::register and
 * ConnectController::submitConnectRegister. Both surfaces validate the same
 * input, dedupe against existing users by email, and create a User + Login row.
 */
class RegistrationService
{
    public function __construct(
        EntityManager $entityManager,
        private UserRepository $users,
        private UserLoginRepository $logins,
    ) {}

    /**
     * @return array{ok: true, user: UserEntity, login: UserLoginEntity}
     *         |array{ok: false, error: string}
     */
    public function register(string $firstName, string $lastName, string $email, string $password): array
    {
        if (empty($firstName) || empty($lastName) || empty($email) || empty($password)) {
            return ['ok' => false, 'error' => 'All fields are required'];
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['ok' => false, 'error' => 'Invalid email format'];
        }
        if ($this->users->userExists($email)) {
            return ['ok' => false, 'error' => 'Email already registered'];
        }
        $user  = $this->users->createLocalUser($email, $firstName, $lastName);
        $login = $this->logins->createLocalLogin($user, $password);
        return ['ok' => true, 'user' => $user, 'login' => $login];
    }
}
