<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Persistence;

use Amtgard\ActiveRecordOrm\Entity\Policy\RepositoryPolicy;
use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\ActiveRecordOrm\Interface\DataAccessPolicy;
use Amtgard\ActiveRecordOrm\Repository\Database;
use Amtgard\ActiveRecordOrm\Schema\FieldDefinition;
use Amtgard\ActiveRecordOrm\Schema\FieldType;
use Amtgard\ActiveRecordOrm\Schema\TableSchema;
use Amtgard\IdP\Persistence\Server\Entities\Repository\UserClientAuthorization;
use Amtgard\IdP\Persistence\Server\Repositories\UserClientAuthorizationRepository;
use PHPUnit\Framework\TestCase;

class UserClientAuthorizationTableSchema extends TableSchema
{
    public function __construct()
    {
        $this->tableName = 'user_client_authorizations';
        $this->fields = [
            'user_identifier' => FieldDefinition::builder()->name('user_identifier')->type(FieldType::STRING)->build(),
            'client_id' => FieldDefinition::builder()->name('client_id')->type(FieldType::INTEGER)->build(),
            'created_at' => FieldDefinition::builder()->name('created_at')->type(FieldType::DATETIME)->build(),
        ];
        $this->primaryKey = FieldDefinition::builder()->name('id')->type(FieldType::INTEGER)->build();
    }
}

class UserClientAuthorizationRepositoryTest extends TestCase
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

    public function testAuthorizePersistsEntityWithCreatedAt(): void
    {
        $captured = null;

        $repository = $this->getMockBuilder(UserClientAuthorizationRepository::class)
            ->onlyMethods(['persist', 'hasAuthorization'])
            ->disableOriginalConstructor()
            ->getMock();

        $repository->expects($this->once())
            ->method('hasAuthorization')
            ->with('user-123', 456)
            ->willReturn(false);

        $repository->expects($this->once())
            ->method('persist')
            ->willReturnCallback(function (UserClientAuthorization $entity) use (&$captured) {
                $captured = $entity;
                return $entity;
            });

        $repository->authorize('user-123', 456);

        $this->assertInstanceOf(UserClientAuthorization::class, $captured);
        $this->assertSame('user-123', $captured->getUserIdentifier());
        $this->assertSame(456, $captured->getClientDbId());
        $this->assertInstanceOf(\DateTimeInterface::class, $captured->getCreatedAt());
    }

    public function testAuthorizeSkipsPersistWhenAuthorizationAlreadyExists(): void
    {
        $repository = $this->getMockBuilder(UserClientAuthorizationRepository::class)
            ->onlyMethods(['persist', 'hasAuthorization'])
            ->disableOriginalConstructor()
            ->getMock();

        $repository->expects($this->once())
            ->method('hasAuthorization')
            ->with('user-123', 456)
            ->willReturn(true);

        $repository->expects($this->never())
            ->method('persist');

        $repository->authorize('user-123', 456);
    }
}
