<?php
declare(strict_types=1);

namespace Amtgard\IdP\Utility\Security;

/**
 * Shared validation for social OAuth2 provider callbacks.
 */
class OAuthCallbackValidator
{
    public static function validate(array $queryParams, string $providerName, string $redirectUrl = '/auth/login'): ?string
    {
        $providerError = ScriptAlertResponse::oauthProviderErrorIfPresent($queryParams, $providerName, $redirectUrl);
        if ($providerError !== null) {
            return $providerError;
        }

        if (!OAuth2StateManager::validateAndConsume($queryParams['state'] ?? null)) {
            return ScriptAlertResponse::invalidOAuthState($redirectUrl);
        }

        return null;
    }
}
