<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Services;

use Amtgard\IdP\Services\OrkService;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;

class OrkServiceTest extends TestCase
{
    private $logger;
    private $clientMock;
    private $service;

    protected function setUp(): void
    {
        $_ENV['ORK_API_USER_AGENT'] = 'TestAgent';
        $_ENV['ORK_API_REFERER'] = 'TestReferer';

        $this->logger = $this->createMock(LoggerInterface::class);
        $this->service = new OrkService($this->logger);

        $this->clientMock = $this->createMock(Client::class);

        // Inject the mocked Guzzle client using Reflection
        $reflector = new \ReflectionClass(OrkService::class);
        $property = $reflector->getProperty('tempClient');
        $property->setAccessible(true);
        $property->setValue($this->service, $this->clientMock);
    }

    public function testConstructorThrowsExceptionOnMissingConfig(): void
    {
        unset($_ENV['ORK_API_USER_AGENT']);
        $this->expectException(\RuntimeException::class);
        new OrkService($this->logger);
    }

    public function testAuthorizeSuccess(): void
    {
        $responseMock = $this->createMock(ResponseInterface::class);
        $streamMock = $this->createMock(StreamInterface::class);
        
        $responseJson = json_encode([
            'Status' => ['Status' => 0],
            'Token' => 'test-token'
        ]);
        
        $streamMock->method('getContents')->willReturn($responseJson);
        $responseMock->method('getBody')->willReturn($streamMock);

        $this->clientMock->expects($this->once())
            ->method('get')
            ->with(self::anything(), $this->callback(function ($options) use ($responseMock) {
                // Assert that the stats callback is executed
                if (isset($options['on_stats'])) {
                    $request = $this->createMock(\Psr\Http\Message\RequestInterface::class);
                    $uri = new \GuzzleHttp\Psr7\Uri('http://test-url');
                    $request->method('getUri')->willReturn($uri);
                    $stats = new \GuzzleHttp\TransferStats($request, $responseMock);
                    $options['on_stats']($stats);
                }
                return true;
            }))
            ->willReturn($responseMock);

        $result = $this->service->authorize('user', 'pass');
        $this->assertIsArray($result);
        $this->assertSame(0, $result['Status']['Status']);
    }

    public function testAuthorizeFailure(): void
    {
        $responseMock = $this->createMock(ResponseInterface::class);
        $streamMock = $this->createMock(StreamInterface::class);
        
        $responseJson = json_encode([
            'Status' => ['Status' => 1]
        ]);
        
        $streamMock->method('getContents')->willReturn($responseJson);
        $responseMock->method('getBody')->willReturn($streamMock);

        $this->clientMock->expects($this->once())
            ->method('get')
            ->with(self::anything(), $this->anything())
            ->willReturn($responseMock);

        $result = $this->service->authorize('user', 'pass');
        $this->assertNull($result);
    }

    public function testAuthorizeException(): void
    {
        $request = $this->createMock(\Psr\Http\Message\RequestInterface::class);
        $this->clientMock->expects($this->once())
            ->method('get')
            ->with(self::anything(), $this->anything())
            ->willThrowException(new RequestException('Error', $request));

        $result = $this->service->authorize('user', 'pass');
        $this->assertNull($result);
    }

    public function testGetPlayerSuccess(): void
    {
        $responseMock = $this->createMock(ResponseInterface::class);
        $streamMock = $this->createMock(StreamInterface::class);
        
        $responseJson = json_encode([
            'Status' => ['Status' => 0],
            'Player' => ['name' => 'John']
        ]);
        
        $streamMock->method('getContents')->willReturn($responseJson);
        $responseMock->method('getBody')->willReturn($streamMock);

        $this->clientMock->expects($this->once())
            ->method('get')
            ->with(self::anything(), $this->anything())
            ->willReturn($responseMock);

        $result = $this->service->getPlayer('token', 123);
        $this->assertIsArray($result);
        $this->assertSame('John', $result['name']);
    }

    public function testGetPlayerException(): void
    {
        $request = $this->createMock(\Psr\Http\Message\RequestInterface::class);
        $this->clientMock->expects($this->once())
            ->method('get')
            ->with(self::anything(), $this->anything())
            ->willThrowException(new RequestException('Error', $request));

        $result = $this->service->getPlayer('token', 123);
        $this->assertNull($result);
    }

    public function testGetParkShortInfoSuccess(): void
    {
        $responseMock = $this->createMock(ResponseInterface::class);
        $streamMock = $this->createMock(StreamInterface::class);
        
        $responseJson = json_encode([
            'Status' => ['Status' => 0],
            'Park' => ['name' => 'Sherwood']
        ]);
        
        $streamMock->method('getContents')->willReturn($responseJson);
        $responseMock->method('getBody')->willReturn($streamMock);

        $this->clientMock->expects($this->once())
            ->method('get')
            ->with(self::anything(), $this->callback(function ($options) use ($responseMock) {
                if (isset($options['on_stats'])) {
                    $request = $this->createMock(\Psr\Http\Message\RequestInterface::class);
                    $uri = new \GuzzleHttp\Psr7\Uri('http://test-url');
                    $request->method('getUri')->willReturn($uri);
                    $stats = new \GuzzleHttp\TransferStats($request, $responseMock);
                    $options['on_stats']($stats);
                }
                return true;
            }))
            ->willReturn($responseMock);

        $result = $this->service->getParkShortInfo(456);
        $this->assertIsArray($result);
        $this->assertSame(0, $result['Status']['Status']);
    }

    public function testGetParkShortInfoException(): void
    {
        $request = $this->createMock(\Psr\Http\Message\RequestInterface::class);
        $this->clientMock->expects($this->once())
            ->method('get')
            ->with(self::anything(), $this->anything())
            ->willThrowException(new RequestException('Error', $request));

        $result = $this->service->getParkShortInfo(456);
        $this->assertNull($result);
    }
}
