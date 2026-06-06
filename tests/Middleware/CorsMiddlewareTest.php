<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Middleware;

use Amtgard\IdP\Middleware\CorsMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CorsMiddlewareTest extends TestCase
{
    public function testProcessOptionsRequest(): void
    {
        $middleware = new CorsMiddleware();

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('OPTIONS');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $response = $middleware->process($request, $handler);

        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertSame('*', $response->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertSame('X-Requested-With, Content-Type, Accept, Origin, Authorization', $response->getHeaderLine('Access-Control-Allow-Headers'));
        $this->assertSame('GET, POST, PUT, DELETE, PATCH, OPTIONS', $response->getHeaderLine('Access-Control-Allow-Methods'));
    }

    public function testProcessStandardRequest(): void
    {
        $middleware = new CorsMiddleware();

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');

        $responseMock = $this->createMock(ResponseInterface::class);
        $responseMock->method('withHeader')->willReturnSelf();

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
            ->method('handle')
            ->with($request)
            ->willReturn($responseMock);

        $response = $middleware->process($request, $handler);
        $this->assertSame($responseMock, $response);
    }
}
