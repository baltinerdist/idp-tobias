<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Middleware {

    use Amtgard\IdP\Middleware\JsonBodyParserMiddleware;
    use PHPUnit\Framework\TestCase;
    use Psr\Http\Message\ResponseInterface;
    use Psr\Http\Message\ServerRequestInterface;
    use Psr\Http\Server\RequestHandlerInterface;

    class JsonBodyParserMiddlewareTest extends TestCase
    {
        public function testProcessNonJson(): void
        {
            $middleware = new JsonBodyParserMiddleware();

            $request = $this->createMock(ServerRequestInterface::class);
            $request->method('getHeaderLine')
                ->with('Content-Type')
                ->willReturn('text/html');

            $request->expects($this->never())->method('withParsedBody');

            $responseMock = $this->createMock(ResponseInterface::class);
            $handler = $this->createMock(RequestHandlerInterface::class);
            $handler->method('handle')->with($request)->willReturn($responseMock);

            $response = $middleware->process($request, $handler);
            $this->assertSame($responseMock, $response);
        }

        public function testProcessEmptyJson(): void
        {
            // Set input to empty string using custom flag
            $GLOBALS['mock_json_input'] = '';

            $middleware = new JsonBodyParserMiddleware();

            $request = $this->createMock(ServerRequestInterface::class);
            $request->method('getHeaderLine')
                ->with('Content-Type')
                ->willReturn('application/json');

            $request->expects($this->never())->method('withParsedBody');

            $responseMock = $this->createMock(ResponseInterface::class);
            $handler = $this->createMock(RequestHandlerInterface::class);
            $handler->method('handle')->with($request)->willReturn($responseMock);

            $response = $middleware->process($request, $handler);
            $this->assertSame($responseMock, $response);
        }

        public function testProcessValidJson(): void
        {
            // Set input to valid JSON
            $GLOBALS['mock_json_input'] = '{"foo": "bar"}';

            $middleware = new JsonBodyParserMiddleware();

            $request = $this->createMock(ServerRequestInterface::class);
            $request->method('getHeaderLine')
                ->with('Content-Type')
                ->willReturn('application/json');

            $request->expects($this->once())
                ->method('withParsedBody')
                ->with(['foo' => 'bar'])
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
    function file_get_contents(string $filename) {
        if ($filename === 'php://input') {
            return $GLOBALS['mock_json_input'] ?? '';
        }
        return \file_get_contents($filename);
    }
}
