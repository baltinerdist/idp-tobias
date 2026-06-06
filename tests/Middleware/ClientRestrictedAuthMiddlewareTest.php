<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Middleware;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Middleware\ClientRestrictedAuthMiddleware;
use Amtgard\IdP\Persistence\Server\Repositories\RedisCacheRepository;
use Amtgard\IdP\Utility\AuthorizedClients;
use League\OAuth2\Server\ResourceServer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Exception\HttpUnauthorizedException;

class ClientRestrictedTestUserEntity extends \Amtgard\IdP\Persistence\Client\Entities\UserEntity
{
    private string $testUserId;
    private string $testEmail;

    public function __construct(string $userId, string $email)
    {
        $this->testUserId = $userId;
        $this->testEmail = $email;
    }

    public function getUserId(): string
    {
        return $this->testUserId;
    }

    public function getEmail(): string
    {
        return $this->testEmail;
    }
}

class ClientRestrictedAuthMiddlewareTest extends TestCase
{
    private $entityManager;
    private $logger;
    private $resourceServer;
    private $validClients;
    private $redisCacheRepository;
    private $request;
    private $handler;
    private $response;
    private $middleware;

    protected function setUp(): void
    {
        $devKeysDir = dirname(__DIR__, 2) . '/dev-keys';
        if (!file_exists('/tmp/private.key') && file_exists($devKeysDir . '/private.key')) {
            @copy($devKeysDir . '/private.key', '/tmp/private.key');
        }
        if (!file_exists('/tmp/public.key') && file_exists($devKeysDir . '/public.key')) {
            @copy($devKeysDir . '/public.key', '/tmp/public.key');
        }

        $this->entityManager = $this->createMock(EntityManager::class);
        \Amtgard\ActiveRecordOrm\EntityManager::configure($this->entityManager, true);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->resourceServer = $this->createMock(ResourceServer::class);
        $this->validClients = AuthorizedClients::builder()
            ->clientIds(['valid-client'])
            ->build();
        $this->redisCacheRepository = $this->createMock(RedisCacheRepository::class);
        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->handler = $this->createMock(RequestHandlerInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);

        $this->middleware = new ClientRestrictedAuthMiddleware(
            $this->entityManager,
            $this->logger,
            $this->resourceServer,
            $this->validClients,
            $this->redisCacheRepository
        );
    }

    public function testProcessCallsHandlerWhenSessionClientIdIsValid(): void
    {
        @session_start();
        $_SESSION['client_id'] = 'valid-client';



        $this->handler->expects($this->once())
            ->method('handle')
            ->with($this->request)
            ->willReturn($this->response);

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame($this->response, $result);
    }

    public function testProcessThrowsUnauthorizedOnMissingJwt(): void
    {
        @session_start();
        $_SESSION['client_id'] = 'invalid-client';


        $this->request->method('getHeaderLine')->with('Authorization')->willReturn('');

        $this->expectException(HttpUnauthorizedException::class);
        $this->middleware->process($this->request, $this->handler);
    }

    public function testProcessSuccessWithCacheHit(): void
    {
        @session_start();
        $_SESSION['client_id'] = 'invalid-client'; // Force checking JWT

        $jwt = $this->generateValidJwt('user-123', 'valid-client');
        $this->request->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn("Bearer {$jwt}");

        $this->redisCacheRepository->expects($this->once())
            ->method('isUserInCache')
            ->with('user-123')
            ->willReturn(true);

        $this->handler->expects($this->once())
            ->method('handle')
            ->with($this->request)
            ->willReturn($this->response);

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame($this->response, $result);
    }

    public function testProcessSuccessWithCacheMiss(): void
    {
        @session_start();
        $_SESSION['client_id'] = 'invalid-client'; // Force checking JWT

        $jwt = $this->generateValidJwt('user-123', 'valid-client');
        $this->request->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn("Bearer {$jwt}");

        $this->redisCacheRepository->expects($this->once())
            ->method('isUserInCache')
            ->with('user-123')
            ->willReturn(false);

        $validatedRequest = $this->createMock(ServerRequestInterface::class);
        $validatedRequest->method('getAttribute')->with('oauth_user_id')->willReturn('user-123');

        $this->resourceServer->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($this->request)
            ->willReturn($validatedRequest);

        $userEntity = new ClientRestrictedTestUserEntity('user-123', 'test@example.com');

        $oauthUser = \Amtgard\IdP\Persistence\Server\Entities\OAuth\OAuthUser::builder()
            ->identifier('user-123')
            ->userEntity($userEntity)
            ->build();

        $userRepo = $this->createMock(\Amtgard\IdP\Persistence\Client\Repositories\UserRepository::class);
        $userRepo->method('getUserEntityById')
            ->with('user-123')
            ->willReturn($oauthUser);

        $this->entityManager->method('getRepository')
            ->with(\Amtgard\IdP\Persistence\Client\Repositories\UserRepository::class)
            ->willReturn($userRepo);

        $this->redisCacheRepository->expects($this->once())
            ->method('cacheValidatedUser')
            ->with(
                'user-123',
                'test@example.com',
                $this->isType('string')
            );

        $this->handler->expects($this->once())
            ->method('handle')
            ->with($validatedRequest)
            ->willReturn($this->response);

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame($this->response, $result);
        $this->assertSame('user-123', $_SESSION['user_id']);
        $this->assertSame('valid-client', $_SESSION['client_id']);
    }

    private function generateValidJwt(string $userId, string $clientId): string
    {
        $clock = new \Lcobucci\Clock\SystemClock(new \DateTimeZone("UTC"));
        $config = \Lcobucci\JWT\Configuration::forAsymmetricSigner(
            new \Lcobucci\JWT\Signer\Rsa\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::file('/tmp/private.key'),
            \Lcobucci\JWT\Signer\Key\InMemory::file('/tmp/public.key')
        );

        $now = $clock->now();
        $token = $config->builder()
            ->issuedBy('http://localhost')
            ->permittedFor($clientId)
            ->relatedTo($userId)
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($config->signer(), $config->signingKey());

        return $token->toString();
    }
}
