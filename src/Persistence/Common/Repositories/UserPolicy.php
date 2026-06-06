<?php

namespace Amtgard\IdP\Persistence\Common\Repositories;

use Amtgard\ActiveRecordOrm\Configuration\DataAccessPolicy\UncachedDataAccessPolicy;
use Amtgard\ActiveRecordOrm\Entity\EntityMapper;
use Amtgard\ActiveRecordOrm\Factory\TableFactory;
use Amtgard\ActiveRecordOrm\Interface\EntityInterface;
use Amtgard\ActiveRecordOrm\Repository\Database;
use Amtgard\IAM\Allowance\Policy;
use Amtgard\IAM\ClaimFactory;
use Amtgard\IAM\OrkService;
use Amtgard\IAM\ORN\OrnClassMap;
use Amtgard\IdP\Models\Orn\IdpClaim;
use Amtgard\IdP\Utility\Exception\MalformedUserPolicyException;
use Throwable;

class UserPolicy
{
    private EntityMapper $userClaims;
    public function __construct(Database $database, UncachedDataAccessPolicy $tablePolicy) {
        $this->userClaims = EntityMapper::builder()
            ->table(TableFactory::build($database, $tablePolicy, 'user_policy_claims'))
            ->build();
    }

    public function getUserPolicy(EntityInterface $user): Policy {
        $this->userClaims->clear();
        $this->userClaims->user_id = $user->id;
        $policyClaims = [];
        $this->userClaims->find();
        OrnClassMap::$ORN_CLASS_MAP[OrkService::Idp->value] = IdpClaim::class;
        while ($this->userClaims->next()) {
            try {
                $orn = $this->userClaims->service . $this->userClaims->provisos . $this->userClaims->resource;
                $policyClaims[] = ClaimFactory::createOrn($orn);
            } catch (Throwable $e) {
                throw new MalformedUserPolicyException($e);
            }
        }
        return new Policy($policyClaims);
    }

}