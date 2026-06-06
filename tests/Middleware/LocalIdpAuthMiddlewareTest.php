<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Middleware;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Middleware\LocalIdpAuthMiddleware;
use Amtgard\IdP\Utility\AuthorizedClients;
use League\OAuth2\Server\ResourceServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Slim\Exception\HttpUnauthorizedException;
use Slim\Interfaces\RouteParserInterface;
use Slim\Routing\RouteContext;

class LocalIdpAuthMiddlewareTest extends TestCase
{
    private $entityManager;
    private $logger;
    private $authorizedClients;
    private $resourceServer;
    private $request;
    private $handler;
    private $response;
    private $routeParser;
    private $middleware;

    protected function setUp(): void
    {
        $this->entityManager = $this->createMock(EntityManager::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->authorizedClients = AuthorizedClients::builder()
            ->clientIds(['valid-client'])
            ->build();
        $this->resourceServer = $this->createMock(ResourceServer::class);
        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->handler = $this->createMock(RequestHandlerInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->routeParser = $this->createMock(RouteParserInterface::class);

        $this->middleware = new LocalIdpAuthMiddleware(
            $this->entityManager,
            $this->logger,
            $this->authorizedClients,
            $this->resourceServer
        );
    }

    public function testProcessThrowsUnauthorizedOnBearerTokenHeader(): void
    {
        $this->request->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer token123');

        $this->expectException(HttpUnauthorizedException::class);
        $this->middleware->process($this->request, $this->handler);
    }

    public function testProcessThrowsUnauthorizedOnInvalidClientId(): void
    {
        $this->request->method('getHeaderLine')->with('Authorization')->willReturn('');
        
        $session = ['client_id' => 'unauthorized-client'];
        $this->request->method('getAttribute')->with('session')->willReturn($session);



        $this->expectException(HttpUnauthorizedException::class);
        $this->middleware->process($this->request, $this->handler);
    }

    public function testProcessSuccessWithSessionUserId(): void
    {
        $this->request->method('getHeaderLine')->with('Authorization')->willReturn('');
        
        $session = ['client_id' => 'valid-client', 'user_id' => 'user-123'];
        $this->request->method('getAttribute')->with('session')->willReturn($session);



        $this->handler->expects($this->once())
            ->method('handle')
            ->with($this->request)
            ->willReturn($this->response);

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame($this->response, $result);
    }

    public function testProcessSuccessWithValidTokenFallback(): void
    {
        $this->request->method('getHeaderLine')->with('Authorization')->willReturn('');
        
        $session = ['client_id' => 'valid-client'];
        // Mock getAttribute to return session when queried with 'session'
        $this->request->method('getAttribute')->willReturnMap([
            ['session', null, $session],
            ['oauth_user_id', null, 'user-token-123']
        ]);



        $validatedRequest = $this->createMock(ServerRequestInterface::class);
        $validatedRequest->method('getAttribute')->with('oauth_user_id')->willReturn('user-token-123');

        $this->resourceServer->expects($this->once())
            ->method('validateAuthenticatedRequest')
            ->with($this->request)
            ->willReturn($validatedRequest);

        $this->handler->expects($this->once())
            ->method('handle')
            ->with($validatedRequest)
            ->willReturn($this->response);

        @session_start();
        $_SESSION = [];

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame($this->response, $result);
        $this->assertSame('user-token-123', $_SESSION['user_id']);
    }

    public function testProcessRedirectsToLoginOnFailure(): void
    {
        $this->request->method('getHeaderLine')->with('Authorization')->willReturn('');
        
        $session = ['client_id' => 'valid-client'];
        
        $routingResults = $this->createMock(\Slim\Routing\RoutingResults::class);
        // Mock RouteContext attributes
        $this->request->method('getAttribute')->willReturnMap([
            ['session', null, $session],
            [RouteContext::ROUTING_RESULTS, null, $routingResults],
            [RouteContext::ROUTE_PARSER, null, $this->routeParser]
        ]);

        // Token validation throws exception
        $this->resourceServer->method('validateAuthenticatedRequest')
            ->willThrowException($this->createMock(OAuthServerException::class));

        $this->routeParser->expects($this->once())
            ->method('urlFor')
            ->with('auth.login')
            ->willReturn('/auth/login');

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame(302, $result->getStatusCode());
        $this->assertSame('/auth/login', $result->getHeaderLine('Location'));
    }
}
