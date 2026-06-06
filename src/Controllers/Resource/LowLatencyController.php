<?php

namespace Amtgard\IdP\Controllers\Resource;

use Amtgard\IdP\Persistence\Server\Repositories\RedisCacheRepository;
use Amtgard\IdP\Utility\CachedValidatedUserEntity;
use Amtgard\IdP\Utility\Jwt;
use Amtgard\IdP\Utility\PubSubQueueHandle;
use Amtgard\SetQueue\PubSubQueue;
use OpenApi\Attributes as OA;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Exception\HttpUnauthorizedException;

class LowLatencyController
{
    private RedisCacheRepository $redisCacheRepository;
    private PubSubQueue $redisPubSubQueue;
    private PubSubQueueHandle $pubSubQueueHandle;

    public function __construct(
        RedisCacheRepository $redisCacheRepository,
        PubSubQueue $redisPubSubQueue,
        PubSubQueueHandle $pubSubQueueHandle
    ) {
        $this->redisCacheRepository = $redisCacheRepository;
        $this->redisPubSubQueue = $redisPubSubQueue;
        $this->pubSubQueueHandle = $pubSubQueueHandle;
    }

    #[OA\Get(
        path: '/resources/validate',
        operationId: 'validate',
        summary: 'Validate a JWT and get user information',
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
                        ]
                    )
                )
            ),
            new OA\Response(response: 401, description: 'Unauthorized'),
        ]
    )]
    public function validate(Request $request, Response $response): Response
    {
        $challengeJwt = Jwt::getBearerJwt($request);

        if (!$challengeJwt || !Jwt::validateJwtSignature($challengeJwt)) {
            throw new HttpUnauthorizedException($request, "Not authorized.");
        }

        $payload = Jwt::parseJwt($challengeJwt);
        $sessionUserId = isset($_SESSION['user_id']) ? (string) $_SESSION['user_id'] : null;
        $tokenUserId = isset($payload['sub']) ? (string) $payload['sub'] : null;

        if ($sessionUserId === null || $tokenUserId === null || $sessionUserId !== $tokenUserId) {
            throw new HttpUnauthorizedException($request, "Not authorized.");
        }

        /** @var CachedValidatedUserEntity|null $user */
        $user = $this->redisCacheRepository->getUser($sessionUserId);

        if (!$user) {
            $user = CachedValidatedUserEntity::builder()
                ->userId($sessionUserId)
                ->email($_SESSION['user_email'] ?? ($payload['email'] ?? ''))
                ->jwt($challengeJwt)
                ->build();
            $this->redisCacheRepository->setUser($user);
        }

        $cachedJwt = $user->getJwt() ?? $challengeJwt;
        if ($user->getJwt() === null) {
            $this->redisCacheRepository->cacheValidatedUser(
                $user->getUserId(),
                $user->getEmail(),
                $challengeJwt
            );
        }

        if (!Jwt::validateJwt($challengeJwt, $cachedJwt)) {
            throw new HttpUnauthorizedException($request, "Not authorized.");
        }

        $userData = [
            'id' => $user->getUserId(),
            'email' => $user->getEmail(),
            'jwt' => $cachedJwt
        ];

        $handle = $this->pubSubQueueHandle->getHandle();
        $this->redisPubSubQueue->publish($handle, $user->getUserId(), $user->getEmail());

        $response->getBody()->write(json_encode($userData));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
