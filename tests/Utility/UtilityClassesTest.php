<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Utility;

use Amtgard\IdP\Persistence\Client\Entities\UserEntity;
use Amtgard\IdP\Persistence\Common\Repositories\UserPolicy;
use Amtgard\IdP\Utility\AuthorizedClients;
use Amtgard\IdP\Utility\CachedValidatedUserEntity;
use Amtgard\IdP\Utility\Constants;
use Amtgard\IdP\Utility\PubSubQueueHandle;
use Amtgard\IdP\Utility\UserAuthority;
use PHPUnit\Framework\TestCase;

class UtilityClassesTest extends TestCase
{
    public function testAuthorizedClients(): void
    {
        $clients = AuthorizedClients::builder()
            ->clientIds(['client-a', 'client-b'])
            ->build();

        $this->assertSame(['client-a', 'client-b'], $clients->getClientIds());
    }

    public function testCachedValidatedUserEntity(): void
    {
        $entity = CachedValidatedUserEntity::builder()
            ->userId('user-1')
            ->email('test@example.com')
            ->jwt('jwt-string')
            ->build();

        $this->assertSame('user-1', $entity->getUserId());
        $this->assertSame('test@example.com', $entity->getEmail());
        $this->assertSame('jwt-string', $entity->getJwt());
        $this->assertTrue($entity->hasJwt());
    }

    public function testCachedValidatedUserEntityWithoutJwt(): void
    {
        $entity = CachedValidatedUserEntity::builder()
            ->userId('user-1')
            ->email('test@example.com')
            ->build();

        $this->assertFalse($entity->hasJwt());
        $this->assertNull($entity->getJwt());
    }

    public function testCachedValidatedUserEntitySurvivesUnserializeWithoutJwt(): void
    {
        $entity = CachedValidatedUserEntity::builder()
            ->userId('user-1')
            ->email('test@example.com')
            ->build();

        $restored = unserialize(serialize($entity));

        $this->assertFalse($restored->hasJwt());
        $this->assertNull($restored->getJwt());
    }

    public function testConstants(): void
    {
        $this->assertSame('amtgard-idp-client-id', Constants::$AMTGARD_IDP_CLIENT_ID);
    }

    public function testPubSubQueueHandle(): void
    {
        $handle = PubSubQueueHandle::builder()
            ->handle('my-handle')
            ->build();

        $this->assertSame('my-handle', $handle->getHandle());
    }

    public function testUserAuthorityIsAdmin(): void
    {
        $user = $this->createMock(UserEntity::class);
        $userPolicy = $this->createMock(UserPolicy::class);
        $policyMock = $this->createMock(\Amtgard\IAM\Allowance\Policy::class);

        $userPolicy->expects($this->once())
            ->method('getUserPolicy')
            ->with($user)
            ->willReturn($policyMock);

        $policyMock->expects($this->once())
            ->method('isAuthorized')
            ->with($this->isInstanceOf(\Amtgard\IdP\Models\Orn\IdpRequirement::class))
            ->willReturn(true);

        $authority = new UserAuthority($userPolicy);
        $this->assertTrue($authority->isAdmin($user));
    }
}
