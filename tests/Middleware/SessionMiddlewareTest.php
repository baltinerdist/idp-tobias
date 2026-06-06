<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Middleware {

    use Amtgard\IdP\Middleware\SessionMiddleware;
    use PHPUnit\Framework\TestCase;
    use Psr\Http\Message\ResponseInterface;
    use Psr\Http\Message\ServerRequestInterface;
    use Psr\Http\Server\RequestHandlerInterface;

    class SessionMiddlewareTest extends TestCase
    {
        public function testProcessSessionActive(): void
        {
            $GLOBALS['mock_session_active'] = true;

            $middleware = new SessionMiddleware();

            $_SESSION = ['foo' => 'bar'];

            $request = $this->createMock(ServerRequestInterface::class);
            $request->expects($this->once())
                ->method('withAttribute')
                ->with('session', ['foo' => 'bar'])
                ->willReturnSelf();

            $responseMock = $this->createMock(ResponseInterface::class);
            $handler = $this->createMock(RequestHandlerInterface::class);
            $handler->method('handle')->with($request)->willReturn($responseMock);

            $response = $middleware->process($request, $handler);
            $this->assertSame($responseMock, $response);
        }

        public function testProcessSessionInactive(): void
        {
            $GLOBALS['mock_session_active'] = false;

            $middleware = new SessionMiddleware();

            $_SESSION = ['foo' => 'baz'];

            $request = $this->createMock(ServerRequestInterface::class);
            $request->expects($this->once())
                ->method('withAttribute')
                ->with('session', ['foo' => 'baz'])
                ->willReturnSelf();

            $responseMock = $this->createMock(ResponseInterface::class);
            $handler = $this->createMock(RequestHandlerInterface::class);
            $handler->method('handle')->with($request)->willReturn($responseMock);

            $response = $middleware->process($request, $handler);
            $this->assertSame($responseMock, $response);
        }
    }
}

namespace Amtgard\IdP\Middleware {
    function session_status() {
        return ($GLOBALS['mock_session_active'] ?? true) ? \PHP_SESSION_ACTIVE : \PHP_SESSION_NONE;
    }

    function session_start() {
        return true;
    }
}
