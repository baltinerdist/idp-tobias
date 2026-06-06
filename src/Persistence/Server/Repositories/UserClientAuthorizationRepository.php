<?php

namespace Amtgard\IdP\Persistence\Server\Repositories;

use Amtgard\ActiveRecordOrm\Attribute\RepositoryOf;
use Amtgard\ActiveRecordOrm\Entity\Repository\Repository;
use Amtgard\ActiveRecordOrm\Interface\EntityRepositoryInterface;
use Amtgard\IdP\Persistence\Server\Entities\Repository\UserClientAuthorization;

#[RepositoryOf('user_client_authorizations', UserClientAuthorization::class)]
class UserClientAuthorizationRepository extends Repository implements EntityRepositoryInterface
{
    static function getTableName()
    {
        return 'user_client_authorizations';
    }

    public static function getEntityClass()
    {
        return UserClientAuthorization::class;
    }

    public function hasAuthorization(string $userIdentifier, int $clientDbId): bool
    {
        $this->clear();
        $this->user_identifier = $userIdentifier;
        $this->client_id = $clientDbId;
        return $this->find() > 0;
    }

    public function authorize(string $userIdentifier, int $clientDbId): void
    {
        if ($this->hasAuthorization($userIdentifier, $clientDbId)) {
            return;
        }

        $auth = UserClientAuthorization::builder()
            ->userIdentifier($userIdentifier)
            ->clientDbId($clientDbId)
            ->createdAt(new \DateTimeImmutable())
            ->build();

        $this->persist($auth);
    }

    public function revokeAuthorization(string $userIdentifier, int $clientDbId): void
    {
        $this->clear();
        $this->query("DELETE FROM user_client_authorizations WHERE user_identifier = :user_identifier AND client_id = :client_id");
        $this->user_identifier = $userIdentifier;
        $this->client_id = $clientDbId;
        $this->execute();
    }
}
