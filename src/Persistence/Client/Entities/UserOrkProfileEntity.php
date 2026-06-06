<?php

namespace Amtgard\IdP\Persistence\Client\Entities;

use Amtgard\ActiveRecordOrm\Attribute\EntityOf;
use Amtgard\ActiveRecordOrm\Attribute\Field;
use Amtgard\ActiveRecordOrm\Attribute\PrimaryKey;
use Amtgard\ActiveRecordOrm\Entity\Repository\RepositoryEntity;
use Amtgard\IdP\Persistence\Client\Repositories\UserOrkProfileRepository;
use Amtgard\Traits\Builder\Builder;
use Amtgard\Traits\Builder\Data;
use Amtgard\Traits\Builder\ToBuilder;
use DateTime;

#[EntityOf(UserOrkProfileRepository::class)]
class UserOrkProfileEntity extends RepositoryEntity
{
    use Builder, ToBuilder, Data;

    #[PrimaryKey]
    private int $id;

    #[Field('user_id')]
    private int $userId;

    #[Field('linked_via')]
    private ?string $linkedVia;

    #[Field('ork_token')]
    private string $orkToken;

    #[Field('mundane_id')]
    private int $mundaneId;

    #[Field('username')]
    private string $username;

    #[Field('persona')]
    private string $persona;

    #[Field('suspended')]
    private int $suspended;

    #[Field('suspended_at')]
    private ?\DateTimeInterface $suspendedAt;

    #[Field('suspended_until')]
    private ?\DateTimeInterface $suspendedUntil;

    #[Field('email')]
    private ?string $email;

    #[Field('park_id')]
    private ?int $parkId;

    #[Field('park_name')]
    private ?string $parkName;

    #[Field('kingdom_id')]
    private ?int $kingdomId;

    #[Field('kingdom_name')]
    private ?string $kingdomName;

    #[Field('dues_through')]
    private ?\DateTimeInterface $duesThrough;

    #[Field('heraldry')]
    private ?string $heraldry;

    #[Field('image')]
    private ?string $image;

    #[Field('created_at')]
    private ?\DateTimeInterface $createdAt;

    #[Field('updated_at')]
    private ?\DateTimeInterface $updatedAt;

    public function getUserId(): int
    {
        return $this->userId;
    }

    public function setUserId(int $userId): void
    {
        $this->userId = $userId;
    }

    public function getOrkToken(): string
    {
        return $this->orkToken;
    }

    public function setOrkToken(string $orkToken): void
    {
        $this->orkToken = $orkToken;
    }

    public function getMundaneId(): int
    {
        return $this->mundaneId;
    }

    public function setMundaneId(int $mundaneId): void
    {
        $this->mundaneId = $mundaneId;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function setUsername(string $username): void
    {
        $this->username = $username;
    }

    public function getPersona(): string
    {
        return $this->persona;
    }

    public function setPersona(string $persona): void
    {
        $this->persona = $persona;
    }

    public function getSuspended(): int
    {
        return $this->suspended;
    }

    public function setSuspended(int $suspended): void
    {
        $this->suspended = $suspended;
    }

    public function getSuspendedAt(): ?DateTime
    {
        return $this->suspendedAt;
    }

    public function setSuspendedAt(?DateTime $suspendedAt): void
    {
        $this->suspendedAt = $suspendedAt;
    }

    public function getSuspendedUntil(): ?DateTime
    {
        return $this->suspendedUntil;
    }

    public function setSuspendedUntil(?DateTime $suspendedUntil): void
    {
        $this->suspendedUntil = $suspendedUntil;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(?string $email): void
    {
        $this->email = $email;
    }

    public function getParkId(): ?int
    {
        return $this->parkId;
    }

    public function setParkId(?int $parkId): void
    {
        $this->parkId = $parkId;
    }

    public function getParkName(): ?string
    {
        return $this->parkName;
    }

    public function setParkName(?string $parkName): void
    {
        $this->parkName = $parkName;
    }

    public function getKingdomId(): ?int
    {
        return $this->kingdomId;
    }

    public function setKingdomId(?int $kingdomId): void
    {
        $this->kingdomId = $kingdomId;
    }

    public function getKingdomName(): ?string
    {
        return $this->kingdomName;
    }

    public function setKingdomName(?string $kingdomName): void
    {
        $this->kingdomName = $kingdomName;
    }

    public function getDuesThrough(): ?DateTime
    {
        return $this->duesThrough;
    }

    public function setDuesThrough(?DateTime $duesThrough): void
    {
        $this->duesThrough = $duesThrough;
    }

    public function getHeraldry(): ?string
    {
        return $this->heraldry;
    }

    public function setHeraldry(?string $heraldry): void
    {
        $this->heraldry = $heraldry;
    }

    public function getImage(): ?string
    {
        return $this->image;
    }

    public function setImage(?string $image): void
    {
        $this->image = $image;
    }

    public function getCreatedAt(): ?DateTime
    {
        return $this->createdAt;
    }

    public function setCreatedAt(?DateTime $createdAt): void
    {
        $this->createdAt = $createdAt;
    }

    public function getUpdatedAt(): ?DateTime
    {
        return $this->updatedAt;
    }

    public function setUpdatedAt(?DateTime $updatedAt): void
    {
        $this->updatedAt = $updatedAt;
    }
}
