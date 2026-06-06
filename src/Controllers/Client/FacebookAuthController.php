<?php

namespace Amtgard\IdP\Controllers\Client;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Models\AmtgardIdpJwt;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use Amtgard\IdP\Utility\Security\OAuth2StateManager;
use Amtgard\IdP\Utility\Security\OAuthCallbackValidator;
use Amtgard\IdP\Utility\Security\ScriptAlertResponse;
use League\OAuth2\Client\Provider\Facebook;
use Optional\Optional;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;

class FacebookAuthController extends BaseAuthController
{
    private UserRepository $users;
    private UserLoginRepository $logins;
    private Facebook $facebookProvider;

    public function __construct(
        EntityManager $entityManager,
        UserRepository $users,
        UserLoginRepository $userLoginRepository,
        LoggerInterface $logger,
        AmtgardIdpJwt $amtgardIdpJwt,
        Facebook $facebookProvider
    ) {
        parent::__construct($logger, $amtgardIdpJwt);
        $this->users = $users;
        $this->logins = $userLoginRepository;
        $this->facebookProvider = $facebookProvider;
    }


    /**
     * Redirect to Facebook for authentication.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function redirectToFacebook(Request $request, Response $response): Response
    {
        $authUrl = $this->facebookProvider->getAuthorizationUrl([
            'scope' => ['email', 'public_profile'],
        ]);

        OAuth2StateManager::store($this->facebookProvider->getState());

        return $response
            ->withHeader('Location', $authUrl)
            ->withStatus(302);
    }

    /**
     * Handle the callback from Facebook.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function handleFacebookCallback(Request $request, Response $response): Response
    {
        $queryParams = $request->getQueryParams();

        $validationResult = OAuthCallbackValidator::validate($queryParams, 'Facebook');

        if ($validationResult !== null) {
            $response->getBody()->write($validationResult);
            return $response;
        }

        try {
            // Get access token
            $token = $this->facebookProvider->getAccessToken('authorization_code', [
                'code' => $queryParams['code']
            ]);

            // Exchange for long-lived token
            $token = $this->facebookProvider->getLongLivedAccessToken($token->getToken());

            // Get user details
            $user = $this->facebookProvider->getResourceOwner($token);
            $userData = $user->toArray();

            $this->logger->debug('Facebook user data: ' . json_encode($userData));

            $user = Optional::ofNullable($this->users->getUserByEmail($userData['email']))
                ->orElseGet(function () use ($userData) {
                    return $this->users->createUserFromFacebookData($userData);
                });

            $login = Optional::ofNullable($this->logins->getLoginByProviderId($userData['id']))
                ->map(function ($login) use ($user, $token) {
                    $login->setUser($user);
                    return $this->logins->updateLoginTokens($login, fn($t) => $t->getToken(), $token);
                })
                ->orElseGet(function () use ($user, $userData, $token) {
                    return $this->logins->createLoginFromFacebookData($user, $userData, $token);
                });

            return $this->finalizeAuthorization($login, $request, $response);
        } catch (\Exception $e) {
            $this->logger->error('Facebook authentication error: ' . $e->getMessage());

            $response->getBody()->write(
                ScriptAlertResponse::alertAndRedirect($e->getMessage(), '/auth/login')
            );
            return $response;
        }
    }

}