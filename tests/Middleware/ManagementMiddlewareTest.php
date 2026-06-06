<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Middleware;

use Amtgard\IdP\Middleware\ManagementMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class ManagementMiddlewareTest extends TestCase
{
    private $oldKey;

    protected function setUp(): void
    {
        $this->oldKey = $_ENV['MANAGEMENT_KEY'] ?? null;
    }

    protected function tearDown(): void
    {
        if ($this->oldKey !== null) {
            $_ENV['MANAGEMENT_KEY'] = $this->oldKey;
        } else {
            unset($_ENV['MANAGEMENT_KEY']);
        }
    }

    public function testProcessNoKeyConfigured(): void
    {
        unset($_ENV['MANAGEMENT_KEY']);

        $middleware = new ManagementMiddleware();
        $request = $this->createMock(ServerRequestInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $response = $middleware->process($request, $handler);
        $this->assertSame(500, $response->getStatusCode());
    }

    public function testProcessKeyTooShort(): void
    {
        $_ENV['MANAGEMENT_KEY'] = 'short-key';

        $middleware = new ManagementMiddleware();
        $request = $this->createMock(ServerRequestInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $response = $middleware->process($request, $handler);
        $this->assertSame(500, $response->getStatusCode());
    }

    public function testProcessUnauthorized(): void
    {
        $_ENV['MANAGEMENT_KEY'] = str_repeat('a', 32);

        $middleware = new ManagementMiddleware();
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['key' => 'wrong-key']);
        $handler = $this->createMock(RequestHandlerInterface::class);

        $response = $middleware->process($request, $handler);
        $this->assertSame(403, $response->getStatusCode());
    }

    public function testProcessSuccess(): void
    {
        $key = str_repeat('a', 32);
        $_ENV['MANAGEMENT_KEY'] = $key;

        $middleware = new ManagementMiddleware();
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn(['key' => $key]);

        $responseMock = $this->createMock(ResponseInterface::class);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->with($request)->willReturn($responseMock);

        $response = $middleware->process($request, $handler);
        $this->assertSame($responseMock, $response);
    }
}
