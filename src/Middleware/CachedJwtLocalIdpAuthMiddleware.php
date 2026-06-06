<?php

namespace Amtgard\IdP\Middleware;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Persistence\Server\Repositories\RedisCacheRepository;
use Amtgard\IdP\Utility\AuthorizedClients;
use Amtgard\IdP\Utility\CachedValidatedUserEntity;
use Amtgard\IdP\Utility\Jwt;
use Amtgard\IdP\Utility\Utility;
use League\OAuth2\Server\ResourceServer;
use Optional\Optional;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Exception\HttpUnauthorizedException;

class CachedJwtLocalIdpAuthMiddleware extends LocalIdpAuthMiddleware
{
    protected LoggerInterface $logger;
    private RedisCacheRepository $redisCacheRepository;
    protected ResourceServer $resourceServer;
    protected AuthorizedClients $authorizedClients;

    public function __construct(EntityManager $em,
                                LoggerInterface $logger,
                                RedisCacheRepository $redisCacheRepository,
                                AuthorizedClients $authorizedClients,
                                ResourceServer $resourceServer) {
        parent::__construct($em, $logger, $authorizedClients, $resourceServer);
        $this->logger = $logger;
        $this->redisCacheRepository = $redisCacheRepository;
        $this->authorizedClients = $authorizedClients;
        $this->resourceServer = $resourceServer;
    }
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $jwt = Optional::ofNullable(Jwt::validateJwtRequest($request))->orElseThrow(new HttpUnauthorizedException($request, "Not authorized."));
        $payload = Optional::ofNullable(value: Jwt::parseJwt($jwt))->orElseThrow(new HttpUnauthorizedException($request, "Not authorized."));
        $oauthUserId = Optional::ofNullable($payload['sub'])->orElseThrow(new HttpUnauthorizedException($request, "Not authorized."));
        $clientId = Optional::ofNullable($payload['aud'])->orElseThrow(new HttpUnauthorizedException($request, "Not authorized."));

        if ($oauthUserId && $this->redisCacheRepository->isUserInCache($oauthUserId)) {
            $_SESSION['user_id'] = $oauthUserId;
            $_SESSION['client_id'] = $clientId;
            return $handler->handle($request);
        } else {
            $request = $this->resourceServer->validateAuthenticatedRequest($request);
            $_SESSION['user_id'] = $request->getAttribute('oauth_user_id');
            $_SESSION['client_id'] = $clientId;
            $user = Utility::getAuthenticatedUser();
            $this->redisCacheRepository->cacheValidatedUser(
                $user->getUserId(),
                $user->getEmail() ?? '',
                $jwt
            );
            return $handler->handle($request);
        }
    }
}
