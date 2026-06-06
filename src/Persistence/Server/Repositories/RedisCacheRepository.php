<?php

namespace Amtgard\IdP\Persistence\Server\Repositories;

use Amtgard\IdP\Utility\CachedValidatedUserEntity;
use Psr\Log\LoggerInterface;
use Redis;

class RedisCacheRepository
{
    private LoggerInterface $logger;
    private Redis $redis;

    public function __construct(LoggerInterface $logger, Redis $redis) {
        $this->logger = $logger;
        $this->redis = $redis;
    }

    public function isUserInCache(string $userId): bool {
        return $this->redis->get($userId) ? true : false;
    }

    public function getUser(string $userId): ?CachedValidatedUserEntity {
        $cached = $this->redis->get($userId);
        if (!$cached) {
            return null;
        }

        $user = unserialize($cached);
        if (!$user instanceof CachedValidatedUserEntity) {
            return null;
        }

        if (method_exists($user, '__wakeup')) {
            $user->__wakeup();
        }

        return $user;
    }

    public function setUser(CachedValidatedUserEntity $userEntity): void {
        $this->redis->set($userEntity->getUserId(), serialize($userEntity));
    }

    public function cacheValidatedUser(string $userId, string $email, string $jwt): void
    {
        $this->setUser(CachedValidatedUserEntity::builder()
            ->userId($userId)
            ->email($email)
            ->jwt($jwt)
            ->build());
    }

    public function queueUserValidation(string $userId, string $userEmail) {

    }
}