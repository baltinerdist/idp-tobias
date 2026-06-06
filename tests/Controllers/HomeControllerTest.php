<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Controllers;

use Amtgard\IdP\Controllers\HomeController;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Twig\Environment as TwigEnvironment;

class HomeControllerTest extends TestCase
{
    public function testIndex(): void
    {
        $twig = $this->createMock(TwigEnvironment::class);
        $twig->expects($this->once())
            ->method('render')
            ->with('home.twig', $this->callback(function ($context) {
                return array_key_exists('isLoggedIn', $context);
            }))
            ->willReturn('home template');

        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $stream = $this->createMock(StreamInterface::class);

        $response->method('getBody')->willReturn($stream);
        $stream->expects($this->once())
            ->method('write')
            ->with('home template');

        $controller = new HomeController($twig);
        $result = $controller->index($request, $response);

        $this->assertSame($response, $result);
    }
}
