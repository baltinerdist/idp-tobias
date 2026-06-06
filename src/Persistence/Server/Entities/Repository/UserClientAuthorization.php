<?php

namespace Amtgard\IdP\Persistence\Server\Entities\Repository;

use Amtgard\ActiveRecordOrm\Attribute\EntityOf;
use Amtgard\ActiveRecordOrm\Attribute\Field;
use Amtgard\ActiveRecordOrm\Attribute\PrimaryKey;
use Amtgard\ActiveRecordOrm\Entity\Repository\RepositoryEntity;
use Amtgard\IdP\Persistence\Server\Repositories\UserClientAuthorizationRepository;
use Amtgard\Traits\Builder\Builder;
use Amtgard\Traits\Builder\Data;

#[EntityOf(UserClientAuthorizationRepository::class)]
class UserClientAuthorization extends RepositoryEntity
{
    use Builder, Data;

    #[PrimaryKey]
    protected int $id;

    #[Field('user_identifier')]
    protected string $userIdentifier;

    #[Field('client_id')]
    protected int $clientDbId;

    #[Field('created_at')]
    protected ?\DateTimeInterface $createdAt = null;
}
