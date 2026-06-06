<?php

namespace Amtgard\IdP\Utility;

use Amtgard\Traits\Builder\Builder;
use Amtgard\Traits\Builder\Getter;

class CachedValidatedUserEntity
{
    use Builder, Getter;
    private string $userId;
    private string $email;
    private ?string $jwt = null;

    public function hasJwt(): bool
    {
        return isset($this->jwt);
    }

    public function getJwt(): ?string
    {
        return $this->hasJwt() ? $this->jwt : null;
    }

    public function __wakeup(): void
    {
        if (!isset($this->jwt)) {
            $this->jwt = null;
        }
    }
}
