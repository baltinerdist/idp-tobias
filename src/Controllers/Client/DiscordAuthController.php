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
use Optional\Optional;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;
use Wohali\OAuth2\Client\Provider\Discord;

class DiscordAuthController extends BaseAuthController
{
    private UserRepository $users;
    private UserLoginRepository $logins;
    private Discord $discordProvider;

    public function __construct(
        EntityManager $entityManager,
        UserRepository $users,
        UserLoginRepository $userLoginRepository,
        LoggerInterface $logger,
        AmtgardIdpJwt $amtgardIdpJwt,
        Discord $discordProvider
    ) {
        parent::__construct($logger, $amtgardIdpJwt);
        $this->users = $users;
        $this->logins = $userLoginRepository;
        $this->discordProvider = $discordProvider;
    }


    /**
     * Redirect to Discord for authentication.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function redirectToDiscord(Request $request, Response $response): Response
    {
        $authUrl = $this->discordProvider->getAuthorizationUrl([
            'scope' => ['identify', 'email']
        ]);

        OAuth2StateManager::store($this->discordProvider->getState());

        $queryParams = $request->getQueryParams();
        $_SESSION['redirect'] = RedirectValidator::sanitizeOrNull($queryParams['redirect'] ?? null);
        $_SESSION['jwtpublickey'] = $queryParams['jwtpublickey'] ?? null;

        return $response
            ->withHeader('Location', $authUrl)
            ->withStatus(302);
    }

    /**
     * Handle the callback from Discord.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function handleDiscordCallback(Request $request, Response $response): Response
    {
        $queryParams = $request->getQueryParams();

        $validationResult = OAuthCallbackValidator::validate($queryParams, 'Discord');

        if ($validationResult !== null) {
            $response->getBody()->write($validationResult);
            return $response;
        }

        try {
            // Get access token
            $token = $this->discordProvider->getAccessToken('authorization_code', [
                'code' => $queryParams['code']
            ]);

            // Get user details
            $discordUser = $this->discordProvider->getResourceOwner($token);
            $userData = $discordUser->toArray();

            $this->logger->debug('Discord user data: ' . json_encode($userData));

            $email = $userData['email'] ?? null;
            if (!$email) {
                throw new \Exception("Email permission denied or not provided by Discord.");
            }

            $user = Optional::ofNullable($this->users->getUserByEmail($email))
                ->orElseGet(function () use ($userData) {
                    // Map Discord fields to Google-like fields for createUserFromGoogleData if generic,
                    // or implement createUserFromDiscordData. Ideally reuse or adapt.
                    // Discord doesn't give first/last names easily, usually just username.
                    // We might need to handle this distribution carefully.
                    // For now, let's assume we map username to firstName and leave lastName empty or placeholder.
    
                    return $this->users->createUserFromGoogleData([
                        'email' => $userData['email'],
                        'given_name' => $userData['username'],
                        'family_name' => '', // Discord doesn't separate names
                        'picture' => $userData['avatar']
                            ? sprintf('https://cdn.discordapp.com/avatars/%s/%s.png', $userData['id'], $userData['avatar'])
                            : 'https://cdn.discordapp.com/embed/avatars/0.png'
                    ]);
                });

            $login = Optional::ofNullable($this->logins->getLoginByProviderId($userData['id']))
                ->map(function ($login) use ($user, $token) {
                    $login->setUser($user);
                    return $this->logins->updateLoginTokens($login, fn($t) => $t->getRefreshToken(), $token);
                })
                ->orElseGet(function () use ($user, $userData, $token) {
                    return $this->logins->createLoginFromDiscordData($user, $userData, $token);
                });

            return $this->finalizeAuthorization($login, $request, $response);
        } catch (\Exception $e) {
            $this->logger->error('Discord authentication error: ' . $e->getTraceAsString());

            $response->getBody()->write(
                ScriptAlertResponse::alertAndRedirect($e->getMessage(), '/auth/login?policy')
            );
            return $response;
        }
    }
}
