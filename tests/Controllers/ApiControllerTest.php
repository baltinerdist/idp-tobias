<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Controllers;

use Amtgard\IdP\Controllers\Api\ApiController;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;

class ApiControllerTest extends TestCase
{
    public function testIsAuthorizedFalse(): void
    {
        \Amtgard\IdP\Utility\Utility::configureIamClasses();
        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $stream = $this->createMock(StreamInterface::class);

        $request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'policy' => '[]',
                'requirement' => 'Idp:0:0:0:0:IDP/EditClient'
            ]);

        $response->method('getBody')->willReturn($stream);
        $response->expects($this->once())
            ->method('withHeader')
            ->with('Content-Type', 'application/json')
            ->willReturnSelf();

        $stream->expects($this->once())
            ->method('write')
            ->with(json_encode(['is_authorized' => false]));

        $controller = new ApiController();
        $result = $controller->isAuthorized($request, $response);

        $this->assertSame($response, $result);
    }
}
