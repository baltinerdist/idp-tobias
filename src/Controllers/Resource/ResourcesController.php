<?php

namespace Amtgard\IdP\Controllers\Resource;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\ActiveRecordOrm\Repository\Database;
use Amtgard\IdP\Models\AmtgardIdpJwt;
use Amtgard\IdP\Persistence\Client\Entities\UserEntity;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserOrkProfileRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use Amtgard\IdP\Persistence\Server\Repositories\RedisCacheRepository;
use Amtgard\IdP\Persistence\Server\Repositories\UserClientAuthorizationRepository;
use Amtgard\IdP\Services\OrkService;
use Amtgard\IdP\Utility\PubSubQueueHandle;
use Amtgard\IdP\Utility\UserAuthority;
use Amtgard\IdP\Utility\Exception\MalformedUserPolicyException;
use Amtgard\IdP\Utility\Utility;
use Amtgard\SetQueue\PubSubQueue;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use OpenApi\Attributes as OA;
use Optional\Optional;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;
use Twig\Environment as TwigEnvironment;

class ResourcesController
{
    private TwigEnvironment $twig;

    protected LoggerInterface $logger;
    private ClientRepositoryInterface $clientRepository;
    private Database $database;
    private PubSubQueue $redisPubSubQueue;
    private PubSubQueueHandle $pubSubQueueHandle;
    private OrkService $orkService;
    private UserOrkProfileRepository $orkProfileRepository;
    private UserRepository $userRepository;
    private UserClientAuthorizationRepository $userClientAuthorizationRepository;
    private UserLoginRepository $userLoginRepository;
    private RedisCacheRepository $redisCacheRepository;
    private AmtgardIdpJwt $amtgardIdpJwt;
    private UserAuthority $userAuthority;


    public function __construct(
        EntityManager $em,
        LoggerInterface $logger,
        TwigEnvironment $twig,
        ClientRepositoryInterface $clientRepository,
        PubSubQueue $redisPubSubQueue,
        PubSubQueueHandle $pubSubQueueHandle,
        RedisCacheRepository $redisCacheRepository,
        Database $database,
        OrkService $orkService,
        UserOrkProfileRepository $orkProfileRepository,
        UserRepository $userRepository,
        UserClientAuthorizationRepository $userClientAuthorizationRepository,
        UserLoginRepository $userLoginRepository,
        AmtgardIdpJwt $amtgardIdpJwt,
        UserAuthority $userAuthority
    ) {
        $this->logger = $logger;
        $this->twig = $twig;
        $this->clientRepository = $clientRepository;
        $this->database = $database;
        $this->redisPubSubQueue = $redisPubSubQueue;
        $this->pubSubQueueHandle = $pubSubQueueHandle;
        $this->orkService = $orkService;
        $this->orkProfileRepository = $orkProfileRepository;
        $this->userRepository = $userRepository;
        $this->userClientAuthorizationRepository = $userClientAuthorizationRepository;
        $this->userLoginRepository = $userLoginRepository;
        $this->redisCacheRepository = $redisCacheRepository;
        $this->amtgardIdpJwt = $amtgardIdpJwt;
        $this->userAuthority = $userAuthority;
    }

    #[OA\Get(
        path: '/resources/jwt',
        operationId: 'getJwt',
        summary: 'Get a JWT for the authenticated user',
        security: [['bearerAuth' => []]],
        responses: [
            new OA\Response(
                response: 200,
                description: 'JWT response',
                content: new OA\MediaType(
                    mediaType: 'application/json',
                    schema: new OA\Schema(
                        properties: [
                            new OA\Property(property: 'jwt', type: 'string'),
                        ]
                    )
                )
            ),
            new OA\Response(response: 401, description: 'Unauthorized'),
        ]
    )]
    public function getJwt(Request $request, Response $response): Response
    {
        $user = Utility::getAuthenticatedUser();
        if (!$user) {
            return $response->withStatus(401);
        }

        try {
            $jwt = $this->amtgardIdpJwt->buildAuthorizationJwt($user);
        } catch (MalformedUserPolicyException $e) {
            $this->logger->error('Malformed IDP access policy fetching JWT', [
                'email' => $user->getEmail(),
                'detail' => $e->getPrevious()?->getMessage(),
            ]);
            return $this->jsonPolicyError($response);
        }

        $this->redisCacheRepository->cacheValidatedUser(
            $user->getUserId(),
            $user->getEmail() ?? '',
            $jwt
        );

        $response->getBody()->write(json_encode(['jwt' => $jwt]));
        return $response->withHeader('Content-Type', 'application/json');
    }

    private function jsonPolicyError(Response $response): Response
    {
        $response->getBody()->write(json_encode([
            'error' => MalformedUserPolicyException::USER_MESSAGE,
        ]));
        return $response->withStatus(422)->withHeader('Content-Type', 'application/json');
    }

    #[OA\Get(
        path: '/resources/userinfo',
        operationId: 'userinfo',
        summary: 'Get user information',
        security: [['bearerAuth' => []]],
        responses: [
            new OA\Response(
                response: 200,
                description: 'User information response',
                content: new OA\MediaType(
                    mediaType: 'application/json',
                    schema: new OA\Schema(
                        properties: [
                            new OA\Property(property: 'id', type: 'integer'),
                            new OA\Property(property: 'email', type: 'string'),
                            new OA\Property(property: 'jwt', type: 'string'),
                            new OA\Property(
                                property: 'ork_profile',
                                type: 'object',
                                properties: [
                                    new OA\Property(property: 'mundane_id', type: 'integer'),
                                    new OA\Property(property: 'username', type: 'string'),
                                    new OA\Property(property: 'persona', type: 'string'),
                                    new OA\Property(property: 'suspended', type: 'boolean'),
                                    new OA\Property(property: 'suspended_at', type: 'string', format: 'date'),
                                    new OA\Property(property: 'suspended_until', type: 'string', format: 'date'),
                                    new OA\Property(property: 'park_id', type: 'integer'),
                                    new OA\Property(property: 'park_name', type: 'string'),
                                    new OA\Property(property: 'kingdom_id', type: 'integer'),
                                    new OA\Property(property: 'kingdom_name', type: 'string'),
                                    new OA\Property(property: 'image', type: 'string'),
                                    new OA\Property(property: 'heraldry', type: 'string'),
                                    new OA\Property(property: 'dues_through', type: 'string', format: 'date'),
                                ]
                            ),
                        ]
                    )
                )
            ),
            new OA\Response(response: 401, description: 'Unauthorized'),
        ]
    )]
    public function userinfo(Request $request, Response $response): Response
    {
        $user = Utility::getAuthenticatedUser();
        if (!$user) {
            return $response->withStatus(401);
        }

        try {
            $jwt = $this->amtgardIdpJwt->buildAuthorizationJwt($user);
        } catch (MalformedUserPolicyException $e) {
            $this->logger->error('Malformed IDP access policy fetching userinfo', [
                'email' => $user->getEmail(),
                'detail' => $e->getPrevious()?->getMessage(),
            ]);
            return $this->jsonPolicyError($response);
        }

        $userData = [
            'id' => $user->getUserId(),
            'email' => $user->getEmail(),
            'jwt' => $jwt
        ];

        $orkProfile = $this->orkProfileRepository->findByUserId($user->getId());
        if ($orkProfile) {
            $userData['ork_profile'] = [
                'mundane_id' => $orkProfile->getMundaneId(),
                'username' => $orkProfile->getUsername(),
                'persona' => $orkProfile->getPersona(),
                'suspended' => (bool) $orkProfile->getSuspended(),
                'suspended_at' => $orkProfile->getSuspendedAt()?->format('Y-m-d'),
                'suspended_until' => $orkProfile->getSuspendedUntil()?->format('Y-m-d'),
                'park_id' => $orkProfile->getParkId(),
                'park_name' => $orkProfile->getParkName(),
                'kingdom_id' => $orkProfile->getKingdomId(),
                'kingdom_name' => $orkProfile->getKingdomName(),
                'image' => $orkProfile->getImage(),
                'heraldry' => $orkProfile->getHeraldry(),
                'dues_through' => $orkProfile->getDuesThrough()?->format('Y-m-d')
            ];
        }

        $response->getBody()->write(json_encode($userData));
        return $response->withHeader('Content-Type', 'application/json');
    }

    #[OA\Get(
        path: '/resources/authorizations',
        operationId: 'authorizations',
        summary: 'Get user authorizations',
        security: [['bearerAuth' => []]],
        responses: [
            new OA\Response(
                response: 200,
                description: 'User authorizations response',
                content: new OA\MediaType(
                    mediaType: 'application/json',
                    schema: new OA\Schema(
                        type: 'array',
                        items: new OA\Items(
                            type: 'object',
                            properties: [
                                new OA\Property(property: 'id', type: 'integer'),
                                new OA\Property(property: 'name', type: 'string'),
                                new OA\Property(property: 'logo', type: 'string'),
                            ]
                        )
                    )
                )
            ),
            new OA\Response(response: 401, description: 'Unauthorized'),
        ]
    )]
    public function authorizations(Request $request, Response $response): Response
    {
        $user = Utility::getAuthenticatedUser();
        if (!$user) {
            return $response->withStatus(401);
        }

        $clients = $this->clientRepository->findActiveClientsForUser($user->getId());

        $response->getBody()->write(json_encode(array_values($clients)));
        return $response->withHeader('Content-Type', 'application/json');
    }

    /**
     * Display the profile page.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function profile(Request $request, Response $response): Response
    {
        $avatarUrl = $_SESSION['avatar_url'] ?? null;
        $params = $request->getQueryParams();
        $error = $params['error'] ?? null;
        $success = $params['success'] ?? null;

        $user = Utility::getAuthenticatedUser();

        $orkProfile = null;
        $userLogins = [];
        $isAdmin = false;
        $clients = [];
        if ($user) {
            try {
                $isAdmin = $this->userAuthority->isAdmin($user);
                $clients = $this->clientRepository->findActiveClientsForUser($user->getId());
                $orkProfile = $this->orkProfileRepository->findByUserId($user->getId());
                $userLogins = $this->userLoginRepository->getAllLoginsForUser($user->getId());
            } catch (MalformedUserPolicyException $e) {
                $this->logger->error('Malformed IDP access policy on profile', [
                    'email' => $user->getEmail(),
                    'detail' => $e->getPrevious()?->getMessage(),
                ]);
                $error = 'malformed_policy';
            }
        }

        $response->getBody()->write($this->twig->render('profile.twig', [
            'avatarUrl' => $avatarUrl,
            'userLogins' => $userLogins,
            'authorizations' => array_values($clients ?? []),
            'orkProfile' => $orkProfile,
            'error' => $error,
            'success' => $success,
            'isAdmin' => $isAdmin
        ]));

        return $response;
    }


    public function linkOrkAccount(Request $request, Response $response): Response
    {
        $params = (array) $request->getParsedBody();
        $username = $params['username'] ?? '';
        $password = $params['password'] ?? '';

        $user = Utility::getAuthenticatedUser();
        if (!$user) {
            return $response->withHeader('Location', '/auth/login')->withStatus(302);
        }

        $authData = $this->orkService->authorize($username, $password);
        if (!$authData) {
            $this->logger->warning('LinkORK: Authorization failed', ['username' => $username]);
            return $response->withHeader('Location', '/resources/profile?error=ork_auth_failed')->withStatus(302);
        }

        $token = $authData['Token'];
        $mundaneId = $authData['UserId'];

        $playerData = $this->orkService->getPlayer($token, $mundaneId);

        if (!$playerData) {
            return $response->withHeader('Location', '/resources/profile?error=ork_player_failed')->withStatus(302);
        }

        $parkData = $this->orkService->getParkShortInfo((int) $playerData['ParkId']);

        $this->orkProfileRepository->saveOrUpdateProfile($playerData, $parkData, $token, $user->getId());

        return $response->withHeader('Location', '/resources/profile?success=linked')->withStatus(302);
    }

    public function refreshOrkAccount(Request $request, Response $response): Response
    {
        $user = Utility::getAuthenticatedUser();
        if (!$user) {
            return $response->withHeader('Location', '/auth/login')->withStatus(302);
        }

        $existing = $this->orkProfileRepository->findByUserId($user->getId());
        if (!$existing) {
            return $response->withHeader('Location', '/resources/profile?error=no_profile')->withStatus(302);
        }

        $token = $existing->getOrkToken();
        $mundaneId = $existing->getMundaneId();

        $playerData = $this->orkService->getPlayer($token, $mundaneId);

        if (!$playerData) {
            $this->logger->warning('RefreshORK: Player fetch failed', ['userId' => $user->getId()]);
            return $response->withHeader('Location', '/resources/profile?error=ork_refresh_failed')->withStatus(302);
        }

        $parkData = $this->orkService->getParkShortInfo((int) $playerData['ParkId']);

        $this->orkProfileRepository->saveOrUpdateProfile($playerData, $parkData, $token, $user->getId());

        return $response->withHeader('Location', '/resources/profile?success=refreshed')->withStatus(302);
    }

    /**
     * Server-to-server endpoint called by ORK to mirror a successful ORK-side
     * link-write back into the IDP. Behind ConfidentialClientBasicAuthMiddleware
     * so only the configured ORK confidential client can invoke it.
     *
     * Request:  { "idp_user_id": "<uuid string>", "mundane_id": 12345 }
     * Response: 204 on success, 400/404/409 on failure (idempotent).
     */
    public function linkOrkProfile(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();
        $idpUserId = Optional::ofNullable($body['idp_user_id'] ?? null)
            ->map(fn($v) => trim((string)$v))
            ->filter(fn($v) => $v !== '')
            ->orElse(null);
        $mundaneId = Optional::ofNullable($body['mundane_id'] ?? null)
            ->map(fn($v) => (int)$v)
            ->filter(fn($v) => $v > 0)
            ->orElse(null);

        if ($idpUserId === null || $mundaneId === null) {
            $response->getBody()->write(json_encode(['error' => 'idp_user_id (string) and mundane_id (positive int) are required']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }

        $userOpt = Optional::ofNullable($this->userRepository->findUserByUserId($idpUserId));
        if (!$userOpt->isPresent()) {
            $this->logger->info('linkOrkProfile unknown idp_user_id', ['idp_user_id' => $idpUserId]);
            $response->getBody()->write(json_encode(['error' => 'unknown idp_user_id']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(404);
        }
        $user = $userOpt->get();

        try {
            $this->orkProfileRepository->linkExistingUserToMundane($user->getId(), $mundaneId, 'mirror');
        } catch (\RuntimeException $e) {
            if (str_contains($e->getMessage(), 'conflict')) {
                $this->logger->warning('linkOrkProfile conflict', [
                    'idp_user_id' => $idpUserId,
                    'requested_mundane_id' => $mundaneId,
                    'msg' => $e->getMessage(),
                ]);
                $response->getBody()->write(json_encode(['error' => 'idp_user_id already linked to a different mundane_id']));
                return $response->withHeader('Content-Type', 'application/json')->withStatus(409);
            }
            throw $e;
        }

        $this->logger->info('linkOrkProfile success', ['idp_user_id' => $idpUserId, 'mundane_id' => $mundaneId]);
        return $response->withStatus(204);
    }

    public function revokeAuthorization(Request $request, Response $response): Response
    {
        /** @var UserEntity $user */
        $user = Utility::getAuthenticatedUser();
        if (!$user) {
            return $response->withHeader('Location', '/auth/login')->withStatus(302);
        }

        $params = (array) $request->getParsedBody();
        $clientId = isset($params['client_id']) ? (int) $params['client_id'] : 0;

        if ($clientId <= 0) {
            return $response->withHeader('Location', '/resources/profile?error=invalid_client')->withStatus(302);
        }

        // We use the email/username as the identifier for authorization
        $this->userClientAuthorizationRepository->revokeAuthorization($user->getUserId(), $clientId);

        // Also revoke access tokens for this client/user combo if needed, 
        // but for now removing the authorization record prevents future token issuance.
        // Implementing full token revocation would require AccessTokenRepository method.

        return $response->withHeader('Location', '/resources/profile?success=revoked')->withStatus(302);
    }
}