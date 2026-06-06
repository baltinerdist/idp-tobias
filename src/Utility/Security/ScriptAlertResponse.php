<?php
declare(strict_types=1);

namespace Amtgard\IdP\Utility\Security;

/**
 * Builds safe HTML responses that display a JavaScript alert and redirect.
 */
class ScriptAlertResponse
{
    public static function alertAndRedirect(string $message, string $redirectUrl): string
    {
        return '
                <script>
                    alert("' . self::escapeForJsString($message) . '");
                    window.location.href = "' . self::escapeForJsString($redirectUrl) . '";
                </script>
            ';
    }

    public static function oauthProviderError(string $providerName, string $error, string $redirectUrl = '/auth/login'): string
    {
        return self::alertAndRedirect(
            "{$providerName} authentication failed: {$error}",
            $redirectUrl
        );
    }

    public static function oauthProviderErrorIfPresent(array $queryParams, string $providerName, string $redirectUrl = '/auth/login'): ?string
    {
        if (!isset($queryParams['error'])) {
            return null;
        }

        return self::oauthProviderError(
            $providerName,
            (string) ($queryParams['error'] ?? 'Unknown Error'),
            $redirectUrl
        );
    }

    public static function invalidOAuthState(string $redirectUrl = '/auth/login'): string
    {
        return self::alertAndRedirect('Invalid state parameter', $redirectUrl);
    }

    private static function escapeForJsString(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
