<?php

namespace Amtgard\IdP\Controllers\Server;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Utility\Security\RedirectValidator;
use Amtgard\IdP\Persistence\Server\Repositories\UserClientAuthorizationRepository;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;
use Twig\Environment as TwigEnvironment;

class OAuth2ServerController
{
    private const STEP_AUTHORIZATION = 'Authorization request (/oauth/authorize)';
    private const STEP_APPROVAL = 'Client approval (/oauth/approve)';
    private const STEP_TOKEN = 'Token exchange (/oauth/token)';

    protected AuthorizationServer $authorizationServer;
    protected ClientRepositoryInterface $clientRepository;
    protected ScopeRepositoryInterface $scopeRepository;
    protected UserRepositoryInterface $userRepository;
    protected TwigEnvironment $view;
    protected LoggerInterface $logger;
    protected ResourceServer $resourceServer;
    protected UserClientAuthorizationRepository $userClientAuthorizationRepository;

    public function __construct(
        LoggerInterface $logger,
        TwigEnvironment $view,
        EntityManager $entityManager,
        AuthorizationServer $authorizationServer,
        ClientRepositoryInterface $clientRepository,
        ScopeRepositoryInterface $scopeRepository,
        UserRepositoryInterface $userRepository,
        ResourceServer $resourceServer,
        UserClientAuthorizationRepository $userClientAuthorizationRepository
    ) {
        $this->logger = $logger;
        $this->view = $view;
        $this->authorizationServer = $authorizationServer;
        $this->clientRepository = $clientRepository;
        $this->scopeRepository = $scopeRepository;
        $this->userRepository = $userRepository;
        $this->resourceServer = $resourceServer;
        $this->userClientAuthorizationRepository = $userClientAuthorizationRepository;
    }

    public function token(Request $request, Response $response): Response
    {
        try {
            return $this->authorizationServer->respondToAccessTokenRequest($request, $response);
        } catch (OAuthServerException $exception) {
            return $exception->generateHttpResponse($response);
        } catch (\Throwable $exception) {
            return $this->renderOAuthTokenError($response, $exception);
        }
    }

    public function approve(Request $request, Response $response): Response
    {
        try {
            if ($request->getMethod() === 'POST') {
                $data = (array) $request->getParsedBody();
                $action = $data['action'] ?? null;
                $callback = RedirectValidator::sanitize($data['callback'] ?? '/', '/');

                if ($action === 'allow') {
                    $_SESSION['approved'] = true;

                    // Get Client ID from query params or session if possible, but safe to assume we can get it from the stored authRequest in session
                    if (isset($_SESSION['authRequest'])) {
                        /** @var AuthorizationRequest $authRequest */
                        $authRequest = unserialize($_SESSION['authRequest']);
                        $clientId = $authRequest->getClient()->getIdentifier();

                        // We need the internal ID of the client for the DB
                        /** @var \Amtgard\IdP\Persistence\Server\Entities\Repository\Client $clientEntity */
                        $clientEntity = $this->clientRepository->fetchBy('identifier', $clientId);

                        if (isset($_SESSION['user_id']) && $clientEntity) {
                            $this->userClientAuthorizationRepository->authorize($_SESSION['user_id'], $clientEntity->getId());
                        }
                    }

                    return $response
                        ->withStatus(302)
                        ->withHeader('Location', $callback);
                }

                // Deny action
                if (isset($_SESSION['authRequest'])) {
                    unset($_SESSION['authRequest']);
                }

                return $response
                    ->withStatus(302)
                    ->withHeader('Location', '/');
            }

            $queryParams = $request->getQueryParams();
            $scopeString = $queryParams['scope'] ?? '';
            $scopes = !empty($scopeString) ? explode(',', $scopeString) : [];
            $clientId = $queryParams['client_id'] ?? 'Unknown Application';
            $client = $this->clientRepository->getClientEntity($clientId);
            $callback = RedirectValidator::sanitize($queryParams['callback'] ?? '/', '/');

            $response->getBody()->write(
                $this->view->render('oauth_approve.twig', [
                    'client_name' => $client->getName(),
                    'scopes' => $scopes,
                    'callback' => $callback
                ])
            );

            return $response;
        } catch (OAuthServerException $exception) {
            return $this->renderOAuthFlowError(
                $response,
                self::STEP_APPROVAL,
                $exception->getMessage(),
                true,
                $exception->getHint(),
                $exception->getHttpStatusCode()
            );
        } catch (\Throwable $exception) {
            return $this->renderOAuthFlowError(
                $response,
                self::STEP_APPROVAL,
                'We could not complete client approval. Please try again or contact an administrator.',
                false,
                null,
                500,
                $exception
            );
        }
    }

    public function clearAuthentication(Request $request, Response $response): Response
    {
        if (isset($_SESSION['user_id'])) {
            unset($_SESSION['user_id']);
        }
        return $response;
    }

    public function clearAuthorizationAndApproval(Request $request, Response $response): Response
    {
        if (isset($_SESSION['authRequest'])) {
            unset($_SESSION['authRequest']);
        }
        if (isset($_SESSION['approved'])) {
            unset($_SESSION['approved']);
        }
        return $response;
    }

    public function authorize(Request $request, Response $response): Response
    {
        try {

            if (!array_key_exists('authRequest', $_SESSION)) {
                /** @var AuthorizationRequest $authRequest */
                $authRequest = $this->authorizationServer->validateAuthorizationRequest($request);
                $_SESSION['authRequest'] = serialize($authRequest);
            } else {
                $authRequest = unserialize($_SESSION['authRequest']);
            }

            if (!$this->userIsAuthenticated($authRequest)) {
                if (isset($_SESSION['user_id'])) {
                    $user = $this->userRepository->getUserEntityById($_SESSION['user_id']);
                    $authRequest->setUser($user);
                    $_SESSION['authRequest'] = serialize($authRequest);
                } else {
                    return $this->authenticateUser($response);
                }
            }

            if (!$this->clientAuthorizationIsApproved($authRequest)) {
                return $this->requestUserAuthorizationOfClient($authRequest, $response);
            }

            return $this->finalizeAuthorization($authRequest, $response);
        } catch (OAuthServerException $exception) {
            $this->logger->error('OAuth authorization server exception', [
                'step' => self::STEP_AUTHORIZATION,
                'message' => $exception->getMessage(),
                'hint' => $exception->getHint(),
            ]);

            if ($request->getMethod() === 'GET') {
                return $this->renderOAuthFlowError(
                    $response,
                    self::STEP_AUTHORIZATION,
                    $exception->getMessage(),
                    true,
                    $exception->getHint(),
                    $exception->getHttpStatusCode()
                );
            }

            return $exception->generateHttpResponse($response);
        } catch (\Throwable $exception) {
            return $this->renderOAuthFlowError(
                $response,
                self::STEP_AUTHORIZATION,
                'We could not complete authorization. Please try again or contact an administrator.',
                false,
                null,
                500,
                $exception
            );
        }
    }

    /**
     * Builds the redirect URL for the OAuth authorization flow after successful authentication.
     *
     * Sets the following query parameters:
     * - scope: Space-separated list of requested scopes (e.g., "profile email").
     * - state: The state parameter provided by the client to maintain state between the request and callback.
     * - response_type: Hardcoded to "code" for the authorization code flow.
     * - approval_prompt: Hardcoded to "auto".
     * - redirect_uri: The URI to redirect the user-agent to after authorization.
     * - client_id: The identifier of the client requesting authorization.
     * - code_challenge: The PKCE code challenge.
     * - code_challenge_method: The PKCE code challenge method (e.g., "S256").
     *
     * @return string The constructed redirect URL.
     */
    public function buildPostAuthenticationRedirectUrl()
    {
        // return "/oauth/authorize?scope=profile email&state=0ed589466400cc4e9c48319b11afe415&response_type=code&approval_prompt=auto&redirect_uri=https://edit.ocho.esdraelon.com&client_id=ork&code_challenge=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

        /** @var AuthorizationRequest $authRequest */
        $authRequest = unserialize($_SESSION['authRequest']);

        $scopes = array_map(function ($scope) {
            return $scope->getIdentifier();
        }, $authRequest->getScopes());

        $params = [
            'scope' => implode(' ', $scopes),
            'state' => $authRequest->getState(),
            'response_type' => 'code',
            'approval_prompt' => 'auto',
            'redirect_uri' => $authRequest->getRedirectUri(),
            'client_id' => $authRequest->getClient()->getIdentifier(),
            'code_challenge' => $authRequest->getCodeChallenge(),
            'code_challenge_method' => $authRequest->getCodeChallengeMethod()
        ];

        return '/oauth/authorize?' . http_build_query($params);
    }

    private function userIsAuthenticated(AuthorizationRequest $authRequest)
    {
        return array_key_exists('user_id', $_SESSION) && !is_null($authRequest->getUser());
    }

    private function authenticateUser(Response $response)
    {
        $redirectUrl = $this->buildPostAuthenticationRedirectUrl();
        $response = $response
            ->withStatus(301)
            ->withHeader('Location', '/auth/login?redirect=' . urlencode($redirectUrl));
        return $response;
    }

    private function clientAuthorizationIsApproved(?AuthorizationRequest $authRequest = null)
    {
        if (array_key_exists('approved', $_SESSION)) {
            return true;
        }

        if ($authRequest && $authRequest->getUser()) {
            /** @var \Amtgard\IdP\Persistence\Server\Entities\Repository\Client $clientEntity */
            $clientEntity = $this->clientRepository->fetchBy('identifier', $authRequest->getClient()->getIdentifier());
            if ($clientEntity) {
                return $this->userClientAuthorizationRepository->hasAuthorization(
                    $authRequest->getUser()->getIdentifier(),
                    $clientEntity->getId()
                );
            }
        }

        return false;
    }

    private function requestUserAuthorizationOfClient(AuthorizationRequest $authRequest, Response $response)
    {
        $authRequest->setUser(
            $this->userRepository->getUserEntityById($_SESSION['user_id'])
        );

        $_SESSION['authRequest'] = serialize($authRequest);

        $response = $response
            ->withStatus(301)
            ->withHeader(
                'Location',
                '/oauth/approve?scope=' . urlencode(implode(
                    ',',
                    array_map(
                        fn($scope) => $scope->getIdentifier(),
                        $authRequest->getScopes()
                    )
                )) . '&callback=/oauth/authorize&client_id=' . $authRequest->getClient()->getIdentifier()
            );
        return $response;
    }

    private function finalizeAuthorization(AuthorizationRequest $authRequest, Response $response)
    {
        $authRequest->setAuthorizationApproved(true);

        $response = $this->authorizationServer->completeAuthorizationRequest($authRequest, $response);

        if (isset($_SESSION['authRequest'])) {
            unset($_SESSION['authRequest']);
        }
        if (isset($_SESSION['approved'])) {
            unset($_SESSION['approved']);
        }

        return $response;
    }

    public function authorizePost(Request $request, Response $response): Response
    {
        return $response;
    }

    private function renderOAuthFlowError(
        Response $response,
        string $step,
        string $message,
        bool $isProtocolError,
        ?string $hint = null,
        int $status = 500,
        ?\Throwable $exception = null
    ): Response {
        if ($exception !== null) {
            $this->logger->error('OAuth flow internal error', [
                'step' => $step,
                'message' => $exception->getMessage(),
                'trace' => $exception->getTraceAsString(),
            ]);
        }

        $response->getBody()->write(
            $this->view->render('oauth_error.twig', [
                'title' => $isProtocolError ? 'OAuth Authorization Error' : 'Authorization Unavailable',
                'step' => $step,
                'message' => $message,
                'hint' => $hint,
                'is_protocol_error' => $isProtocolError,
            ])
        );

        return $response->withStatus($status);
    }

    private function renderOAuthTokenError(Response $response, \Throwable $exception): Response
    {
        $this->logger->error('OAuth token internal error', [
            'step' => self::STEP_TOKEN,
            'message' => $exception->getMessage(),
            'trace' => $exception->getTraceAsString(),
        ]);

        $response->getBody()->write(json_encode([
            'error' => 'server_error',
            'error_description' => 'The authorization server encountered an internal error during token exchange.',
            'oauth_step' => self::STEP_TOKEN,
            'error_type' => 'internal_server_error',
        ]));

        return $response
            ->withStatus(500)
            ->withHeader('Content-Type', 'application/json');
    }

}