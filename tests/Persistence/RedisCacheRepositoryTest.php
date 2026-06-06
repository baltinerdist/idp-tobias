<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Persistence;

use Amtgard\IdP\Persistence\Server\Repositories\RedisCacheRepository;
use Amtgard\IdP\Utility\CachedValidatedUserEntity;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Redis;

class RedisCacheRepositoryTest extends TestCase
{
    private LoggerInterface $logger;
    private Redis $redis;
    private RedisCacheRepository $repository;

    protected function setUp(): void
    {
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->redis = $this->createMock(Redis::class);
        $this->repository = new RedisCacheRepository($this->logger, $this->redis);
    }

    public function testCacheValidatedUserStoresEntityWithJwt(): void
    {
        $this->redis->expects($this->once())
            ->method('set')
            ->with('user-1', $this->callback(function (string $serialized) {
                $entity = unserialize($serialized);
                return $entity instanceof CachedValidatedUserEntity
                    && $entity->getUserId() === 'user-1'
                    && $entity->getEmail() === 'test@example.com'
                    && $entity->getJwt() === 'jwt-token'
                    && $entity->hasJwt();
            }));

        $this->repository->cacheValidatedUser('user-1', 'test@example.com', 'jwt-token');
    }

    public function testGetUserReturnsCachedEntityWithoutJwt(): void
    {
        $entity = CachedValidatedUserEntity::builder()
            ->userId('user-1')
            ->email('test@example.com')
            ->build();

        $this->redis->expects($this->once())
            ->method('get')
            ->with('user-1')
            ->willReturn(serialize($entity));

        $result = $this->repository->getUser('user-1');

        $this->assertInstanceOf(CachedValidatedUserEntity::class, $result);
        $this->assertSame('user-1', $result->getUserId());
        $this->assertSame('test@example.com', $result->getEmail());
        $this->assertFalse($result->hasJwt());
    }

    public function testGetUserReturnsNullWhenNotCached(): void
    {
        $this->redis->expects($this->once())
            ->method('get')
            ->with('missing-user')
            ->willReturn(false);

        $this->assertNull($this->repository->getUser('missing-user'));
    }

    public function testIsUserInCache(): void
    {
        $this->redis->expects($this->once())
            ->method('get')
            ->with('user-1')
            ->willReturn(serialize(CachedValidatedUserEntity::builder()
                ->userId('user-1')
                ->email('test@example.com')
                ->build()));

        $this->assertTrue($this->repository->isUserInCache('user-1'));
    }
}
