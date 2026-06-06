<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Persistence;

use Amtgard\ActiveRecordOrm\Entity\Policy\RepositoryPolicy;
use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\ActiveRecordOrm\Interface\DataAccessPolicy;
use Amtgard\ActiveRecordOrm\Repository\Database;
use Amtgard\IdP\Persistence\Server\Entities\Repository\UserClientAuthorization;
use PHPUnit\Framework\TestCase;

class UserClientAuthorizationEntityTest extends TestCase
{
    protected function setUp(): void
    {
        $database = $this->createMock(Database::class);
        $dataAccessPolicy = $this->createMock(DataAccessPolicy::class);
        $repositoryPolicy = $this->createMock(RepositoryPolicy::class);
        $tableSchema = new UserClientAuthorizationTableSchema();

        $dataAccessPolicy->method('applyTableSchemaPolicy')->willReturn($tableSchema);

        $entityManager = EntityManager::builder()
            ->database($database)
            ->dataAccessPolicy($dataAccessPolicy)
            ->repositoryPolicy($repositoryPolicy)
            ->build();

        EntityManager::configure($entityManager, true);
    }

    public function testEntityAllowsNullCreatedAtForAaroRoundTrip(): void
    {
        $entity = UserClientAuthorization::builder()
            ->userIdentifier('user-123')
            ->clientDbId(456)
            ->build();

        $this->assertNull($entity->getCreatedAt());
    }

    public function testEntityStoresCreatedAtWhenProvided(): void
    {
        $createdAt = new \DateTimeImmutable('2026-06-05T12:00:00+00:00');

        $entity = UserClientAuthorization::builder()
            ->userIdentifier('user-123')
            ->clientDbId(456)
            ->createdAt($createdAt)
            ->build();

        $this->assertSame($createdAt, $entity->getCreatedAt());
    }
}
