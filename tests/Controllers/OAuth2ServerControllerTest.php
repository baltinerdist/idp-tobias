<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Controllers;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Controllers\Server\OAuth2ServerController;
use Amtgard\IdP\Persistence\Server\Repositories\UserClientAuthorizationRepository;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Twig\Environment as TwigEnvironment;

class TestAuthorizationRequest extends \League\OAuth2\Server\RequestTypes\AuthorizationRequest
{
    public function __construct($client = null, $user = null)
    {
        $this->client = $client;
        $this->user = $user;
        $this->scopes = [];
        $this->state = 'test-state';
        $this->redirectUri = 'http://test-redirect';
        $this->codeChallenge = 'test-challenge';
        $this->codeChallengeMethod = 'S256';
    }
}

class TestClient extends \Amtgard\IdP\Persistence\Server\Entities\Repository\Client
{
    private ?int $testId = null;

    public function setId(int $id): self
    {
        $this->testId = $id;
        return $this;
    }

    public function getId(): ?int
    {
        return $this->testId;
    }
}

class OAuth2ServerControllerTest extends TestCase
{
    private $logger;
    private $view;
    private $entityManager;
    private $authorizationServer;
    private $clientRepository;
    private $scopeRepository;
    private $userRepository;
    private $resourceServer;
    private $userClientAuthorizationRepository;
    private $request;
    private $response;
    private $stream;
    private $controller;

    protected function setUp(): void
    {
        @session_start();
        $_SESSION = [];

        $this->logger = $this->createMock(LoggerInterface::class);
        $this->view = $this->createMock(TwigEnvironment::class);
        $this->entityManager = $this->createMock(EntityManager::class);
        $this->authorizationServer = $this->createMock(AuthorizationServer::class);
        $this->clientRepository = $this->createMock(\Amtgard\IdP\Persistence\Server\Repositories\ClientRepository::class);
        $this->scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $this->userRepository = $this->createMock(\Amtgard\IdP\Persistence\Client\Repositories\UserRepository::class);
        $this->resourceServer = $this->createMock(ResourceServer::class);
        $this->userClientAuthorizationRepository = $this->createMock(UserClientAuthorizationRepository::class);

        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->stream = $this->createMock(StreamInterface::class);

        $this->response->method('getBody')->willReturn($this->stream);
        $this->response->method('withHeader')->willReturnSelf();
        $this->response->method('withStatus')->willReturnSelf();
        $this->response->method('withBody')->willReturnSelf();

        $this->controller = new OAuth2ServerController(
            $this->logger,
            $this->view,
            $this->entityManager,
            $this->authorizationServer,
            $this->clientRepository,
            $this->scopeRepository,
            $this->userRepository,
            $this->resourceServer,
            $this->userClientAuthorizationRepository
        );
    }

    public function testTokenFlowSuccess(): void
    {
        $this->authorizationServer->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->with($this->request, $this->response)
            ->willReturn($this->response);

        $result = $this->controller->token($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testTokenFlowOAuthException(): void
    {
        $exception = $this->getMockBuilder(OAuthServerException::class)
            ->disableOriginalConstructor()
            ->getMock();

        $exception->expects($this->once())
            ->method('generateHttpResponse')
            ->willReturn($this->response);

        $this->authorizationServer->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->willThrowException($exception);

        $result = $this->controller->token($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testTokenFlowGeneralException(): void
    {
        $this->authorizationServer->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->willThrowException(new \Exception('Token error'));

        $this->logger->expects($this->once())
            ->method('error')
            ->with(
                'OAuth token internal error',
                $this->callback(function (array $context) {
                    return str_contains($context['step'], '/oauth/token')
                        && $context['message'] === 'Token error';
                })
            );

        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->callback(function (string $json) {
                $data = json_decode($json, true);
                return ($data['error'] ?? null) === 'server_error'
                    && str_contains($data['error_description'] ?? '', 'internal error')
                    && str_contains($data['oauth_step'] ?? '', '/oauth/token');
            }));

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(500)
            ->willReturnSelf();

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Content-Type', 'application/json')
            ->willReturnSelf();

        $result = $this->controller->token($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testApprovePostAllow(): void
    {
        $this->request->method('getMethod')->willReturn('POST');
        $this->request->method('getParsedBody')->willReturn([
            'action' => 'allow',
            'callback' => '/next'
        ]);

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('client-1');

        $clientRecord = new TestClient();
        $clientRecord->setId(456);

        $authRequest = new TestAuthorizationRequest($clientMock);
        $_SESSION['authRequest'] = serialize($authRequest);
        $_SESSION['user_id'] = 123;

        $this->clientRepository->expects($this->once())
            ->method('fetchBy')
            ->with('identifier', 'client-1')
            ->willReturn($clientRecord);

        $this->userClientAuthorizationRepository->expects($this->once())
            ->method('authorize')
            ->with(123, 456);

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Location', '/next')
            ->willReturnSelf();

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(302)
            ->willReturnSelf();

        $result = $this->controller->approve($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertTrue($_SESSION['approved']);
    }

    public function testApprovePostDeny(): void
    {
        $this->request->method('getMethod')->willReturn('POST');
        $this->request->method('getParsedBody')->willReturn([
            'action' => 'deny'
        ]);

        $_SESSION['authRequest'] = 'some-serialized-data';

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Location', '/')
            ->willReturnSelf();

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(302)
            ->willReturnSelf();

        $result = $this->controller->approve($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertArrayNotHasKey('authRequest', $_SESSION);
    }

    public function testApproveGet(): void
    {
        $this->request->method('getMethod')->willReturn('GET');
        $this->request->method('getQueryParams')->willReturn([
            'client_id' => 'client-1',
            'scope' => 'profile,email',
            'callback' => '/next'
        ]);

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getName')->willReturn('Client One');

        $this->clientRepository->expects($this->once())
            ->method('getClientEntity')
            ->with('client-1')
            ->willReturn($clientMock);

        $this->view->expects($this->once())
            ->method('render')
            ->with('oauth_approve.twig', [
                'client_name' => 'Client One',
                'scopes' => ['profile', 'email'],
                'callback' => '/next'
            ])
            ->willReturn('approve form');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('approve form');

        $result = $this->controller->approve($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testClearAuthentication(): void
    {
        $_SESSION['user_id'] = 123;
        $result = $this->controller->clearAuthentication($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertArrayNotHasKey('user_id', $_SESSION);
    }

    public function testClearAuthorizationAndApproval(): void
    {
        $_SESSION['authRequest'] = 'serialized';
        $_SESSION['approved'] = true;

        $result = $this->controller->clearAuthorizationAndApproval($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertArrayNotHasKey('authRequest', $_SESSION);
        $this->assertArrayNotHasKey('approved', $_SESSION);
    }

    public function testAuthorizeUnauthenticatedRedirectsToLogin(): void
    {
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('client-1');

        $authRequest = new TestAuthorizationRequest($clientMock);

        $this->authorizationServer->expects($this->once())
            ->method('validateAuthorizationRequest')
            ->willReturn($authRequest);

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Location', $this->stringContains('/auth/login?redirect='))
            ->willReturnSelf();

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(301)
            ->willReturnSelf();

        $result = $this->controller->authorize($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testAuthorizeAuthenticatedNotApprovedRedirectsToApprove(): void
    {
        $_SESSION['user_id'] = 123;

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('client-1');

        $userMock = $this->createMock(UserEntityInterface::class);
        $userMock->method('getIdentifier')->willReturn('user-123');

        $authRequest = new TestAuthorizationRequest($clientMock, $userMock);

        $this->authorizationServer->expects($this->once())
            ->method('validateAuthorizationRequest')
            ->willReturn($authRequest);

        $clientRecord = new TestClient();
        $clientRecord->setId(456);

        $this->clientRepository->expects($this->once())
            ->method('fetchBy')
            ->with('identifier', 'client-1')
            ->willReturn($clientRecord);

        $this->userClientAuthorizationRepository->expects($this->once())
            ->method('hasAuthorization')
            ->willReturn(false);

        $this->userRepository->expects($this->once())
            ->method('getUserEntityById')
            ->with(123)
            ->willReturn($userMock);

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Location', $this->stringContains('/oauth/approve?'))
            ->willReturnSelf();

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(301)
            ->willReturnSelf();

        $result = $this->controller->authorize($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testAuthorizeSuccess(): void
    {
        $_SESSION['user_id'] = 123;
        $_SESSION['approved'] = true;

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('client-1');

        $userMock = $this->createMock(UserEntityInterface::class);

        $authRequest = new TestAuthorizationRequest($clientMock, $userMock);

        $this->authorizationServer->expects($this->once())
            ->method('validateAuthorizationRequest')
            ->willReturn($authRequest);

        $this->authorizationServer->expects($this->once())
            ->method('completeAuthorizationRequest')
            ->with($authRequest, $this->response)
            ->willReturn($this->response);

        $result = $this->controller->authorize($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testAuthorizeOAuthException(): void
    {
        $exception = new OAuthServerException(
            'OAuth Error',
            0,
            'invalid_request',
            400,
            'Check params'
        );

        $this->authorizationServer->expects($this->once())
            ->method('validateAuthorizationRequest')
            ->willThrowException($exception);

        $this->request->method('getMethod')->willReturn('GET');

        $this->view->expects($this->once())
            ->method('render')
            ->with('oauth_error.twig', $this->callback(function (array $context) {
                return $context['title'] === 'OAuth Authorization Error'
                    && str_contains($context['step'], '/oauth/authorize')
                    && $context['message'] === 'OAuth Error'
                    && $context['hint'] === 'Check params'
                    && $context['is_protocol_error'] === true;
            }))
            ->willReturn('error HTML');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('error HTML');

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(400)
            ->willReturnSelf();

        $result = $this->controller->authorize($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testAuthorizeGeneralException(): void
    {
        $this->authorizationServer->expects($this->once())
            ->method('validateAuthorizationRequest')
            ->willThrowException(new \Exception('Internal error'));

        $this->view->expects($this->once())
            ->method('render')
            ->with('oauth_error.twig', $this->callback(function (array $context) {
                return $context['title'] === 'Authorization Unavailable'
                    && str_contains($context['step'], '/oauth/authorize')
                    && $context['is_protocol_error'] === false;
            }))
            ->willReturn('error HTML');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('error HTML');

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(500)
            ->willReturnSelf();

        $result = $this->controller->authorize($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testApprovePostAllowInternalError(): void
    {
        $this->request->method('getMethod')->willReturn('POST');
        $this->request->method('getParsedBody')->willReturn([
            'action' => 'allow',
            'callback' => '/next'
        ]);

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('client-1');

        $clientRecord = new TestClient();
        $clientRecord->setId(456);

        $authRequest = new TestAuthorizationRequest($clientMock);
        $_SESSION['authRequest'] = serialize($authRequest);
        $_SESSION['user_id'] = 123;

        $this->clientRepository->expects($this->once())
            ->method('fetchBy')
            ->with('identifier', 'client-1')
            ->willReturn($clientRecord);

        $this->userClientAuthorizationRepository->expects($this->once())
            ->method('authorize')
            ->willThrowException(new \TypeError('Cannot assign null to property createdAt'));

        $this->logger->expects($this->once())
            ->method('error')
            ->with(
                'OAuth flow internal error',
                $this->callback(function (array $context) {
                    return str_contains($context['step'], '/oauth/approve')
                        && str_contains($context['message'], 'createdAt');
                })
            );

        $this->view->expects($this->once())
            ->method('render')
            ->with('oauth_error.twig', $this->callback(function (array $context) {
                return $context['title'] === 'Authorization Unavailable'
                    && str_contains($context['message'], 'could not complete client approval')
                    && str_contains($context['step'], '/oauth/approve')
                    && $context['is_protocol_error'] === false;
            }))
            ->willReturn('error HTML');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('error HTML');

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(500)
            ->willReturnSelf();

        $result = $this->controller->approve($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testApprovePostAllowCallsAuthorizeWithSessionUserAndClient(): void
    {
        $this->request->method('getMethod')->willReturn('POST');
        $this->request->method('getParsedBody')->willReturn([
            'action' => 'allow',
            'callback' => '/oauth/authorize',
        ]);

        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('getIdentifier')->willReturn('skbc_dev');

        $clientRecord = new TestClient();
        $clientRecord->setId(789);

        $_SESSION['authRequest'] = serialize(new TestAuthorizationRequest($clientMock));
        $_SESSION['user_id'] = 'user-abc';

        $this->clientRepository->expects($this->once())
            ->method('fetchBy')
            ->with('identifier', 'skbc_dev')
            ->willReturn($clientRecord);

        $this->userClientAuthorizationRepository->expects($this->once())
            ->method('authorize')
            ->with('user-abc', 789);

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Location', '/oauth/authorize')
            ->willReturnSelf();

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(302)
            ->willReturnSelf();

        $result = $this->controller->approve($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertTrue($_SESSION['approved']);
    }

    public function testAuthorizeInternalExceptionOnPostReturnsHtmlErrorPage(): void
    {
        $this->request->method('getMethod')->willReturn('POST');

        $this->authorizationServer->expects($this->once())
            ->method('validateAuthorizationRequest')
            ->willThrowException(new \Exception('Internal error'));

        $this->view->expects($this->once())
            ->method('render')
            ->with('oauth_error.twig', $this->callback(function (array $context) {
                return str_contains($context['step'], '/oauth/authorize')
                    && $context['is_protocol_error'] === false;
            }))
            ->willReturn('error HTML');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('error HTML');

        $result = $this->controller->authorize($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testAuthorizeOAuthExceptionOnPostReturnsOAuthResponse(): void
    {
        $exception = $this->getMockBuilder(OAuthServerException::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->request->method('getMethod')->willReturn('POST');

        $this->authorizationServer->expects($this->once())
            ->method('validateAuthorizationRequest')
            ->willThrowException($exception);

        $exception->expects($this->once())
            ->method('generateHttpResponse')
            ->with($this->response)
            ->willReturn($this->response);

        $this->view->expects($this->never())->method('render');

        $result = $this->controller->authorize($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testAuthorizePost(): void
    {
        $result = $this->controller->authorizePost($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }
}
