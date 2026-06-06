<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Controllers;

use Amtgard\IdP\Controllers\Resource\LowLatencyController;
use Amtgard\IdP\Persistence\Server\Repositories\RedisCacheRepository;
use Amtgard\IdP\Utility\CachedValidatedUserEntity;
use Amtgard\IdP\Utility\PubSubQueueHandle;
use Amtgard\SetQueue\PubSubQueue;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Slim\Exception\HttpUnauthorizedException;

class LowLatencyControllerTest extends TestCase
{
    private $redisCacheRepository;
    private $redisPubSubQueue;
    private $pubSubQueueHandle;
    private $request;
    private $response;
    private $stream;
    private $controller;

    protected function setUp(): void
    {
        // Copy dev-keys to /tmp if not present so signature validation works
        $devKeysDir = dirname(__DIR__, 2) . '/dev-keys';
        if (!file_exists('/tmp/private.key') && file_exists($devKeysDir . '/private.key')) {
            @copy($devKeysDir . '/private.key', '/tmp/private.key');
        }
        if (!file_exists('/tmp/public.key') && file_exists($devKeysDir . '/public.key')) {
            @copy($devKeysDir . '/public.key', '/tmp/public.key');
        }

        $this->redisCacheRepository = $this->createMock(RedisCacheRepository::class);
        $this->redisPubSubQueue = $this->createMock(PubSubQueue::class);
        
        // Instantiate PubSubQueueHandle using its builder
        $this->pubSubQueueHandle = PubSubQueueHandle::builder()
            ->handle('test-handle')
            ->build();

        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->stream = $this->createMock(StreamInterface::class);

        $this->response->method('getBody')->willReturn($this->stream);
        $this->response->method('withHeader')->willReturnSelf();

        $this->controller = new LowLatencyController(
            $this->redisCacheRepository,
            $this->redisPubSubQueue,
            $this->pubSubQueueHandle
        );
    }

    public function testValidateThrowsUnauthorizedWhenNoBearerToken(): void
    {
        $this->request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('');

        $this->redisCacheRepository->expects($this->never())
            ->method('getUser');

        $this->expectException(HttpUnauthorizedException::class);

        $this->controller->validate($this->request, $this->response);
    }

    public function testValidateThrowsUnauthorizedWhenSessionMissing(): void
    {
        $_SESSION = [];

        $jwt = $this->generateValidJwt('user-123', 'test@example.com');
        $this->request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer ' . $jwt);

        $this->redisCacheRepository->expects($this->never())
            ->method('getUser');

        $this->expectException(HttpUnauthorizedException::class);

        $this->controller->validate($this->request, $this->response);
    }

    public function testValidateThrowsUnauthorizedWhenInvalidSignature(): void
    {
        $_SESSION['user_id'] = 'user-123';

        $this->redisCacheRepository->expects($this->never())
            ->method('getUser');

        // Invalid JWT (just a random string)
        $this->request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer invalid.jwt.string');

        $this->expectException(HttpUnauthorizedException::class);

        $this->controller->validate($this->request, $this->response);
    }

    public function testValidateThrowsUnauthorizedWhenMismatchedJwt(): void
    {
        $_SESSION['user_id'] = 'user-123';

        $user = CachedValidatedUserEntity::builder()
            ->userId('user-123')
            ->email('test@example.com')
            ->jwt('mismatched-jwt')
            ->build();

        $this->redisCacheRepository->expects($this->once())
            ->method('getUser')
            ->with('user-123')
            ->willReturn($user);

        // Generate a valid signed JWT but it won't match $user->getJwt()
        $jwt = $this->generateValidJwt('user-123', 'test@example.com');

        $this->request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer ' . $jwt);

        $this->expectException(HttpUnauthorizedException::class);

        $this->controller->validate($this->request, $this->response);
    }

    public function testValidateSuccess(): void
    {
        $_SESSION['user_id'] = 'user-123';

        // Generate a valid JWT
        $jwt = $this->generateValidJwt('user-123', 'test@example.com');

        $user = CachedValidatedUserEntity::builder()
            ->userId('user-123')
            ->email('test@example.com')
            ->jwt($jwt)
            ->build();

        $this->redisCacheRepository->expects($this->once())
            ->method('getUser')
            ->with('user-123')
            ->willReturn($user);

        $this->request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer ' . $jwt);

        $this->redisPubSubQueue->expects($this->once())
            ->method('publish')
            ->with('test-handle', 'user-123', 'test@example.com');

        $this->stream->expects($this->once())
            ->method('write')
            ->with(json_encode([
                'id' => 'user-123',
                'email' => 'test@example.com',
                'jwt' => $jwt
            ]));

        $result = $this->controller->validate($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testValidateSuccessWhenCachedUserMissingJwt(): void
    {
        $_SESSION['user_id'] = 'user-123';

        $jwt = $this->generateValidJwt('user-123', 'test@example.com');

        $user = CachedValidatedUserEntity::builder()
            ->userId('user-123')
            ->email('test@example.com')
            ->build();

        $this->redisCacheRepository->expects($this->once())
            ->method('getUser')
            ->with('user-123')
            ->willReturn($user);

        $this->redisCacheRepository->expects($this->once())
            ->method('cacheValidatedUser')
            ->with('user-123', 'test@example.com', $jwt);

        $this->request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer ' . $jwt);

        $this->redisPubSubQueue->expects($this->once())
            ->method('publish')
            ->with('test-handle', 'user-123', 'test@example.com');

        $this->stream->expects($this->once())
            ->method('write')
            ->with(json_encode([
                'id' => 'user-123',
                'email' => 'test@example.com',
                'jwt' => $jwt
            ]));

        $result = $this->controller->validate($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testValidateSuccessWhenRedisCacheMiss(): void
    {
        $_SESSION['user_id'] = 'user-123';
        $_SESSION['user_email'] = 'test@example.com';

        $jwt = $this->generateValidJwt('user-123', 'test@example.com');

        $this->redisCacheRepository->expects($this->once())
            ->method('getUser')
            ->with('user-123')
            ->willReturn(null);

        $this->redisCacheRepository->expects($this->once())
            ->method('setUser')
            ->with($this->callback(function (CachedValidatedUserEntity $user) use ($jwt) {
                return $user->getUserId() === 'user-123'
                    && $user->getEmail() === 'test@example.com'
                    && $user->getJwt() === $jwt;
            }));

        $this->request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer ' . $jwt);

        $this->redisPubSubQueue->expects($this->once())
            ->method('publish')
            ->with('test-handle', 'user-123', 'test@example.com');

        $this->stream->expects($this->once())
            ->method('write')
            ->with(json_encode([
                'id' => 'user-123',
                'email' => 'test@example.com',
                'jwt' => $jwt
            ]));

        $result = $this->controller->validate($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    private function generateValidJwt(string $userId, string $email): string
    {
        if (!file_exists('/tmp/private.key') || !file_exists('/tmp/public.key')) {
            return 'dummy.jwt.string';
        }

        $clock = new \Lcobucci\Clock\SystemClock(new \DateTimeZone("UTC"));
        $config = \Lcobucci\JWT\Configuration::forAsymmetricSigner(
            new \Lcobucci\JWT\Signer\Rsa\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::file('/tmp/private.key'),
            \Lcobucci\JWT\Signer\Key\InMemory::file('/tmp/public.key')
        );

        $now = $clock->now();
        $token = $config->builder()
            ->issuedBy('http://localhost')
            ->permittedFor('client-1')
            ->relatedTo($userId)
            ->expiresAt($now->modify('+1 hour'))
            ->withClaim('email', $email)
            ->withClaim('policy', '[]')
            ->getToken($config->signer(), $config->signingKey());

        return $token->toString();
    }
}
