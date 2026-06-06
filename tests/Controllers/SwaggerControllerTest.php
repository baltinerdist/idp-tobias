<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Controllers;

use Amtgard\IdP\Controllers\SwaggerController;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Twig\Environment as TwigEnvironment;

class SwaggerControllerTest extends TestCase
{
    private $twig;
    private $request;
    private $response;
    private $stream;
    private $controller;

    protected function setUp(): void
    {
        $this->twig = $this->createMock(TwigEnvironment::class);
        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->stream = $this->createMock(StreamInterface::class);

        $this->response->method('getBody')->willReturn($this->stream);
        $this->response->method('withHeader')->willReturnSelf();
        $this->response->method('withStatus')->willReturnSelf();

        $this->controller = new SwaggerController($this->twig);
    }

    public function testDocumentation(): void
    {
        $this->twig->expects($this->once())
            ->method('render')
            ->with('swagger.twig')
            ->willReturn('swagger view');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('swagger view');

        $result = $this->controller->documentation($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testOpenapi(): void
    {
        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->callback(function ($json) {
                $data = json_decode($json, true);
                return is_array($data) && isset($data['openapi']);
            }));

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Content-Type', 'application/json')
            ->willReturnSelf();

        $result = $this->controller->openapi($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testDocsify(): void
    {
        $this->twig->expects($this->once())
            ->method('render')
            ->with('docsify.twig')
            ->willReturn('docsify shell');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('docsify shell');

        $result = $this->controller->docsify($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testDocsifyContent(): void
    {
        // Our controller looks for templates/api.md relative to src/Controllers
        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->stringContains('Amtgard Identity Provider'));

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Content-Type', 'text/markdown')
            ->willReturnSelf();

        $result = $this->controller->docsifyContent($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testDocsifyContentNotFound(): void
    {
        $filePath = dirname(__DIR__, 2) . '/templates/api.md';
        $bakPath = $filePath . '.bak';
        $renamed = false;
        if (file_exists($filePath)) {
            rename($filePath, $bakPath);
            $renamed = true;
        }

        try {
            $this->stream->expects($this->once())
                ->method('write')
                ->with('Documentation not found.');

            $this->response->expects($this->once())
                ->method('withStatus')
                ->with(404)
                ->willReturnSelf();

            $this->response->expects($this->once())
                ->method('withHeader')
                ->with('Content-Type', 'text/plain')
                ->willReturnSelf();

            $result = $this->controller->docsifyContent($this->request, $this->response);
            $this->assertSame($this->response, $result);
        } finally {
            if ($renamed && file_exists($bakPath)) {
                rename($bakPath, $filePath);
            }
        }
    }
}
