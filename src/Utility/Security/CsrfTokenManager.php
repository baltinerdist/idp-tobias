<?php
declare(strict_types=1);

namespace Amtgard\IdP\Utility\Security;

/**
 * Session-backed CSRF token generation and validation for form submissions.
 */
class CsrfTokenManager
{
    public const TOKEN_FIELD = '_csrf_token';
    private const SESSION_KEY = 'csrf_token';

    public static function generate(): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION[self::SESSION_KEY] = $token;
        return $token;
    }

    public static function getOrCreate(): string
    {
        return $_SESSION[self::SESSION_KEY] ?? self::generate();
    }

    public static function validate(?string $submittedToken): bool
    {
        $expectedToken = $_SESSION[self::SESSION_KEY] ?? null;

        if ($expectedToken === null || $submittedToken === null || $submittedToken === '') {
            return false;
        }

        return hash_equals($expectedToken, $submittedToken);
    }
}
