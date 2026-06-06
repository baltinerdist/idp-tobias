<?php

namespace Amtgard\IdP\Controllers\Client;

use Amtgard\IdP\Models\AmtgardIdpJwt;
use Amtgard\IdP\Persistence\Client\Entities\UserLoginEntity;
use Amtgard\IdP\Utility\Constants;
use Amtgard\IdP\Utility\Exception\MalformedUserPolicyException;
use Amtgard\IdP\Utility\Security\RedirectValidator;
use Amtgard\IdP\Utility\Security\ScriptAlertResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Slim\Routing\RouteContext;

class BaseAuthController
{
    protected LoggerInterface $logger;
    protected AmtgardIdpJwt $amtgardIdpJwt;

    public function __construct(LoggerInterface $logger, AmtgardIdpJwt $amtgardIdpJwt)
    {
        $this->logger = $logger;
        $this->amtgardIdpJwt = $amtgardIdpJwt;
    }

    protected function finalizeAuthorization(UserLoginEntity $login, ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $this->logger->info("User is authenticated; setting session for " . $login->user->getEmail());
        $_SESSION['client_id'] = Constants::$AMTGARD_IDP_CLIENT_ID;
        $_SESSION['user_id'] = $login->user->getUserId();
        $_SESSION['user_email'] = $login->user->getEmail();
        $_SESSION['user_name'] = $login->user->getFullName();
        $_SESSION['avatar_url'] = $login->getAvatarUrl();

        // Redirect to home page
        $routeContext = RouteContext::fromRequest($request);
        $routeParser = $routeContext->getRouteParser();

        $this->logger->info("Building JWT for " . $login->user->getEmail());
        try {
            $jwt = $this->amtgardIdpJwt->buildAuthorizationJwt($login->user);
        } catch (MalformedUserPolicyException $e) {
            $this->logger->error('Malformed IDP access policy at login', [
                'email' => $login->user->getEmail(),
                'detail' => $e->getPrevious()?->getMessage(),
            ]);
            session_unset();

            $response->getBody()->write(
                ScriptAlertResponse::alertAndRedirect(
                    MalformedUserPolicyException::USER_MESSAGE,
                    '/auth/login'
                )
            );
            return $response;
        }

        $profileUrl = $routeParser->urlFor('resources.profile');
        $storedRedirect = RedirectValidator::sanitizeOrNull($_SESSION['redirect'] ?? null);
        $finalizeUrl = $storedRedirect === null
            ? $profileUrl
            : ($storedRedirect . "?jwt=$jwt");

        $this->logger->info("Redirecting user for " . $login->user->getEmail());
        return $response
            ->withHeader('Location', $finalizeUrl)
            ->withStatus(302);
    }

}