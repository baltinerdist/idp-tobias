<?php
declare(strict_types=1);

namespace Amtgard\IdP\Persistence\Client\Repositories;

use Amtgard\ActiveRecordOrm\Attribute\RepositoryOf;
use Amtgard\ActiveRecordOrm\Entity\Repository\Repository;
use Amtgard\ActiveRecordOrm\Interface\EntityRepositoryInterface;
use Amtgard\IdP\Persistence\Client\Entities\UserOrkProfileEntity;
use DateTime;
use Optional\Optional;

#[RepositoryOf("user_ork_profiles", UserOrkProfileEntity::class)]
class UserOrkProfileRepository extends Repository implements EntityRepositoryInterface
{
    public function findByUserId(int $userId): ?UserOrkProfileEntity
    {
        return $this->fetchBy('user_id', $userId);
    }

    private function parseOrkDate(?string $dateStr): ?DateTime
    {
        if (empty($dateStr) || $dateStr === '0000-00-00') {
            return null;
        }
        try {
            return new DateTime($dateStr);
        } catch (\Exception $e) {
            return null;
        }
    }

    public function saveOrUpdateProfile(array $playerData, ?array $parkData, string $token, int $userId): void
    {
        $existing = $this->findByUserId($userId);

        if ($existing) {
            $orkProfile = $existing->toBuilder();
        } else {
            $orkProfile = UserOrkProfileEntity::builder()
                ->userId($userId)
                ->createdAt(new DateTime());
        }

        $orkProfile
            ->orkToken($token)
            ->mundaneId((int) $playerData['MundaneId'])
            ->username($playerData['UserName'])
            ->persona($playerData['Persona'])
            ->suspended((int) $playerData['Suspended'])
            ->email($playerData['Email'])
            ->parkId((int) $playerData['ParkId'])
            ->parkName($parkData['ParkInfo']['ParkName'] ?? null)
            ->kingdomId((int) $playerData['KingdomId'])
            ->kingdomName($parkData['KingdomInfo']['KingdomName'] ?? null)
            ->image($playerData['Image'])
            ->heraldry($playerData['Heraldry'])
            ->suspendedAt($this->parseOrkDate($playerData['SuspendedAt']))
            ->suspendedUntil($this->parseOrkDate($playerData['SuspendedUntil']))
            ->duesThrough($this->parseOrkDate($playerData['DuesThrough']))
            ->updatedAt(new DateTime());

        $entity = $orkProfile->build();

        $this->persist($entity);
    }

    /**
     * Idempotently link an existing IDP user to an ORK mundane.
     *
     * - If no profile exists, create a minimal placeholder row tagged with $linkedVia.
     *   The persona/username/ork_token fields are left blank; they get populated on the
     *   user's next userinfo round-trip via saveOrUpdateProfile().
     * - If a profile exists pointing at the same mundane, no-op.
     * - If a profile exists pointing at a different mundane, throw RuntimeException
     *   with 'conflict' in the message — the caller turns this into a 409 to the client.
     */
    public function linkExistingUserToMundane(int $userId, int $mundaneId, string $linkedVia): void
    {
        $existingOpt = Optional::ofNullable($this->findByUserId($userId));
        if ($existingOpt->isPresent()) {
            $existing = $existingOpt->get();
            if ($existing->getMundaneId() === $mundaneId) {
                return;
            }
            throw new \RuntimeException(
                "conflict: user_id={$userId} is already linked to mundane_id={$existing->getMundaneId()}, refusing to relink to {$mundaneId}"
            );
        }

        $now = new DateTime();
        $entity = UserOrkProfileEntity::builder()
            ->userId($userId)
            ->linkedVia($linkedVia)
            ->orkToken('')
            ->mundaneId($mundaneId)
            ->username('')
            ->persona('')
            ->suspended(0)
            ->email(null)
            ->parkId(null)
            ->kingdomId(null)
            ->createdAt($now)
            ->updatedAt($now)
            ->build();

        // H3: a concurrent caller may have just inserted a row pointing at the
        // same user_id or mundane_id between our findByUserId() above and this
        // persist(). The UNIQUE indexes (migration 20260514140000) make the DB
        // arbitrate. Catch the integrity violation and translate it back into
        // the same idempotent vs. conflict branches the caller already handles.
        try {
            $this->persist($entity);
        } catch (\PDOException $e) {
            $sqlstate = $e->getCode();
            $isIntegrity = $sqlstate === '23000' || str_contains($e->getMessage(), 'Duplicate');
            if (!$isIntegrity) {
                throw $e;
            }
            // Re-read and disambiguate.
            $currentOpt = Optional::ofNullable($this->findByUserId($userId));
            if ($currentOpt->isPresent()) {
                $current = $currentOpt->get();
                if ($current->getMundaneId() === $mundaneId) {
                    return; // idempotent: another request linked the same pair.
                }
                throw new \RuntimeException(
                    "conflict: user_id={$userId} is already linked to mundane_id={$current->getMundaneId()}, refusing to relink to {$mundaneId}"
                );
            }
            // Must be the mundane_id uniqueness — someone else already owns it.
            throw new \RuntimeException(
                "conflict: mundane_id={$mundaneId} is already linked to a different IDP user"
            );
        }
    }

    static function getTableName()
    {
        return 'user_ork_profiles';
    }

    public static function getEntityClass()
    {
        return UserOrkProfileEntity::class;
    }

}
