<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Middleware;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Middleware\LocalAdminUserMiddleware;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use Amtgard\IdP\Utility\UserAuthority;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Interfaces\RouteParserInterface;
use Slim\Routing\RouteContext;

class LocalAdminUserMiddlewareTest extends TestCase
{
    private $entityManager;
    private $userRepository;
    private $userAuthority;
    private $request;
    private $handler;
    private $response;
    private $routeParser;
    private $middleware;

    protected function setUp(): void
    {
        $this->entityManager = $this->createMock(EntityManager::class);
        $this->userRepository = $this->createMock(UserRepository::class);
        $this->userAuthority = $this->createMock(UserAuthority::class);
        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->handler = $this->createMock(RequestHandlerInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->routeParser = $this->createMock(RouteParserInterface::class);

        $this->middleware = new LocalAdminUserMiddleware(
            $this->entityManager,
            $this->userRepository,
            $this->userAuthority
        );
    }

    public function testProcessRedirectsWhenNoUserId(): void
    {
        $routingResults = $this->createMock(\Slim\Routing\RoutingResults::class);
        $this->request->method('getAttribute')->willReturnMap([
            ['session', null, []],
            [RouteContext::ROUTING_RESULTS, null, $routingResults],
            [RouteContext::ROUTE_PARSER, null, $this->routeParser]
        ]);

        $this->routeParser->expects($this->once())
            ->method('urlFor')
            ->with('resources.profile')
            ->willReturn('/resources/profile');

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame(302, $result->getStatusCode());
        $this->assertSame('/resources/profile', $result->getHeaderLine('Location'));
    }

    public function testProcessRedirectsWhenNotAdmin(): void
    {
        $user = $this->createMock(\Amtgard\IdP\Persistence\Client\Entities\UserEntity::class);

        $routingResults = $this->createMock(\Slim\Routing\RoutingResults::class);
        $this->request->method('getAttribute')->willReturnMap([
            ['session', null, ['user_id' => 'user-123']],
            [RouteContext::ROUTING_RESULTS, null, $routingResults],
            [RouteContext::ROUTE_PARSER, null, $this->routeParser]
        ]);

        $this->userRepository->expects($this->once())
            ->method('findUserByUserId')
            ->with('user-123')
            ->willReturn($user);

        $this->userAuthority->expects($this->once())
            ->method('isAdmin')
            ->with($user)
            ->willReturn(false);

        $this->routeParser->expects($this->once())
            ->method('urlFor')
            ->with('resources.profile')
            ->willReturn('/resources/profile');

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame(302, $result->getStatusCode());
    }

    public function testProcessCallsHandlerWhenAdmin(): void
    {
        $user = $this->createMock(\Amtgard\IdP\Persistence\Client\Entities\UserEntity::class);

        $this->request->method('getAttribute')->willReturnMap([
            ['session', null, ['user_id' => 'admin-123']]
        ]);

        $this->userRepository->expects($this->once())
            ->method('findUserByUserId')
            ->with('admin-123')
            ->willReturn($user);

        $this->userAuthority->expects($this->once())
            ->method('isAdmin')
            ->with($user)
            ->willReturn(true);

        $this->handler->expects($this->once())
            ->method('handle')
            ->with($this->request)
            ->willReturn($this->response);

        $result = $this->middleware->process($this->request, $this->handler);
        $this->assertSame($this->response, $result);
    }
}
