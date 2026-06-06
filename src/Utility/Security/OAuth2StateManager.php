<?php
declare(strict_types=1);

namespace Amtgard\IdP\Utility\Security;

/**
 * Manages OAuth2 authorization state parameter storage and validation (CSRF protection).
 */
class OAuth2StateManager
{
    private const SESSION_KEY = 'oauth2state';

    public static function store(string $state): void
    {
        $_SESSION[self::SESSION_KEY] = $state;
    }

    public static function validateAndConsume(?string $receivedState): bool
    {
        $expectedState = $_SESSION[self::SESSION_KEY] ?? null;

        if (empty($receivedState) || $receivedState !== $expectedState) {
            unset($_SESSION[self::SESSION_KEY]);
            return false;
        }

        unset($_SESSION[self::SESSION_KEY]);
        return true;
    }
}
