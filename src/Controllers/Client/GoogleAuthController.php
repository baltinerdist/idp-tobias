<?php

namespace Amtgard\IdP\Controllers\Client;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Models\AmtgardIdpJwt;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use Amtgard\IdP\Utility\Security\OAuth2StateManager;
use Amtgard\IdP\Utility\Security\OAuthCallbackValidator;
use Amtgard\IdP\Utility\Security\RedirectValidator;
use Amtgard\IdP\Utility\Security\ScriptAlertResponse;
use League\OAuth2\Client\Provider\Google;
use Optional\Optional;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;

class GoogleAuthController extends BaseAuthController
{
    private UserRepository $users;
    private UserLoginRepository $logins;
    private Google $googleProvider;

    public function __construct(
        EntityManager $entityManager,
        UserRepository $users,
        UserLoginRepository $userLoginRepository,
        LoggerInterface $logger,
        AmtgardIdpJwt $amtgardIdpJwt,
        Google $googleProvider
    ) {
        parent::__construct($logger, $amtgardIdpJwt);
        $this->users = $users;
        $this->logins = $userLoginRepository;
        $this->googleProvider = $googleProvider;
    }


    /**
     * Redirect to Google for authentication.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function redirectToGoogle(Request $request, Response $response): Response
    {
        $authUrl = $this->googleProvider->getAuthorizationUrl([
            'scope' => ['email', 'profile'],
            'access_type' => 'offline',
            'prompt' => 'consent'
        ]);

        OAuth2StateManager::store($this->googleProvider->getState());

        $queryParams = $request->getQueryParams();
        $_SESSION['redirect'] = RedirectValidator::sanitizeOrNull($queryParams['redirect'] ?? null);
        $_SESSION['jwtpublickey'] = $queryParams['jwtpublickey'] ?? null;

        return $response
            ->withHeader('Location', $authUrl)
            ->withStatus(302);
    }

    /**
     * Handle the callback from Google.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function handleGoogleCallback(Request $request, Response $response): Response
    {
        $queryParams = $request->getQueryParams();

        $validationResult = OAuthCallbackValidator::validate($queryParams, 'Google');

        if ($validationResult !== null) {
            $response->getBody()->write($validationResult);
            return $response;
        }

        try {
            // Get access token
            $token = $this->googleProvider->getAccessToken('authorization_code', [
                'code' => $queryParams['code']
            ]);

            // Get user details
            $googleUser = $this->googleProvider->getResourceOwner($token);
            $userData = $googleUser->toArray();

            $this->logger->debug('Google user data: ' . json_encode($userData));

            $user = Optional::ofNullable($this->users->getUserByEmail($userData['email']))
                ->orElseGet(function () use ($userData) {
                    return $this->users->createUserFromGoogleData($userData);
                });

            $login = Optional::ofNullable($this->logins->getLoginByProviderId($userData['sub']))
                ->map(function ($login) use ($user, $token) {
                    $login->setUser($user);
                    return $this->logins->updateLoginTokens($login, fn($t) => $t->getRefreshToken(), $token);
                })
                ->orElseGet(function () use ($user, $userData, $token) {
                    return $this->logins->createLoginFromGoogleData($user, $userData, $token);
                });

            return $this->finalizeAuthorization($login, $request, $response);
        } catch (\Exception $e) {
            $this->logger->error('Google authentication error: ' . $e->getTraceAsString());

            $response->getBody()->write(
                ScriptAlertResponse::alertAndRedirect($e->getMessage(), '/auth/login?policy')
            );
            return $response;
        }
    }


}