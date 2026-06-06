<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Controllers;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Controllers\Client\AuthController;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use Amtgard\IdP\Persistence\Client\Entities\UserEntity;
use Amtgard\IdP\Persistence\Client\Entities\UserLoginEntity;
use Amtgard\IdP\Models\AmtgardIdpJwt;
use Amtgard\IdP\Utility\Exception\MalformedUserPolicyException;
use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Provider\Google;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Slim\Interfaces\RouteParserInterface;
use Slim\Routing\RouteContext;
use Slim\Routing\RoutingResults;
use Twig\Environment as TwigEnvironment;

class TestUserEntity extends UserEntity
{
    private string $testUserId;
    private string $testEmail;
    private string $testFullName;

    public function __construct(string $userId, string $email, string $fullName)
    {
        $this->testUserId = $userId;
        $this->testEmail = $email;
        $this->testFullName = $fullName;
    }

    public function getUserId(): string
    {
        return $this->testUserId;
    }

    public function getEmail(): string
    {
        return $this->testEmail;
    }

    public function getFullName(): string
    {
        return $this->testFullName;
    }
}

class TestUserLoginEntity extends UserLoginEntity
{
    private string $testPassword;
    private string $testAvatarUrl;
    public $user;

    public function __construct($user, string $password, string $avatarUrl)
    {
        $this->user = $user;
        $this->testPassword = $password;
        $this->testAvatarUrl = $avatarUrl;
    }

    public function getPassword(): ?string
    {
        return $this->testPassword;
    }

    public function getAvatarUrl(): ?string
    {
        return $this->testAvatarUrl;
    }
}

class AuthControllerTest extends TestCase
{
    private $entityManager;
    private $userRepository;
    private $userLoginRepository;
    private $logger;
    private $googleProvider;
    private $facebookProvider;
    private $discordProvider;
    private $amtgardIdpJwt;
    private $twig;
    private $request;
    private $response;
    private $stream;
    private $authController;
    private $routeParser;
    private $routingResults;

    protected function setUp(): void
    {
        @session_start();
        $_SESSION = [];

        $this->entityManager = $this->createMock(EntityManager::class);
        $this->userRepository = $this->createMock(UserRepository::class);
        $this->userLoginRepository = $this->createMock(UserLoginRepository::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->googleProvider = $this->createMock(Google::class);
        $this->facebookProvider = $this->createMock(Facebook::class);
        $this->discordProvider = $this->createMock(\Wohali\OAuth2\Client\Provider\Discord::class);
        $this->amtgardIdpJwt = $this->createMock(AmtgardIdpJwt::class);
        $this->twig = $this->createMock(TwigEnvironment::class);

        $this->request = $this->createMock(ServerRequestInterface::class);
        $this->response = $this->createMock(ResponseInterface::class);
        $this->stream = $this->createMock(StreamInterface::class);
        $this->routeParser = $this->createMock(RouteParserInterface::class);
        $this->routingResults = $this->createMock(RoutingResults::class);

        $this->response->method('getBody')->willReturn($this->stream);
        $this->response->method('withHeader')->willReturnSelf();
        $this->response->method('withStatus')->willReturnSelf();

        // Setup Request attributes for RouteContext::fromRequest
        $this->request->method('getAttribute')
            ->willReturnCallback(function (string $name) {
                if ($name === RouteContext::ROUTE_PARSER) {
                    return $this->routeParser;
                }
                if ($name === RouteContext::ROUTING_RESULTS) {
                    return $this->routingResults;
                }
                return null;
            });

        $this->authController = new AuthController(
            $this->entityManager,
            $this->userRepository,
            $this->userLoginRepository,
            $this->logger,
            $this->googleProvider,
            $this->facebookProvider,
            $this->discordProvider,
            $this->amtgardIdpJwt,
            $this->twig
        );
    }

    public function testLoginForm(): void
    {
        $this->request->expects($this->any())
            ->method('getQueryParams')
            ->willReturn(['redirect' => '/profile', 'jwtpublickey' => 'key']);

        $this->twig->expects($this->once())
            ->method('render')
            ->with('login_form.twig', [
                'redirect' => '/profile',
                'jwtpublickey' => 'key'
            ])
            ->willReturn('login form HTML');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('login form HTML');

        $result = $this->authController->loginForm($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testRegisterForm(): void
    {
        $this->twig->expects($this->once())
            ->method('render')
            ->with('register_form.twig')
            ->willReturn('register form HTML');

        $this->stream->expects($this->once())
            ->method('write')
            ->with('register form HTML');

        $result = $this->authController->registerForm($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testLoginSuccess(): void
    {
        $email = 'test@example.com';
        $password = 'password123';

        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['email' => $email, 'password' => $password]);

        $user = new TestUserEntity('user-1', $email, 'John Doe');
        $login = new TestUserLoginEntity($user, password_hash($password, PASSWORD_BCRYPT), 'http://avatar.url');

        $this->userRepository->expects($this->any())
            ->method('getUserByEmail')
            ->with($email)
            ->willReturn($user);

        $this->userLoginRepository->expects($this->once())
            ->method('getLoginByUser')
            ->with($user)
            ->willReturn($login);

        $this->routeParser->method('urlFor')->willReturn('/resources/profile');

        $this->amtgardIdpJwt->expects($this->once())
            ->method('buildAuthorizationJwt')
            ->with($user)
            ->willReturn('fake-jwt-token');

        $result = $this->authController->login($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertEquals('user-1', $_SESSION['user_id']);
        $this->assertEquals($email, $_SESSION['user_email']);
    }

    public function testLoginMalformedPolicy(): void
    {
        $email = 'test@example.com';
        $password = 'password123';

        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['email' => $email, 'password' => $password]);

        $user = new TestUserEntity('user-1', $email, 'John Doe');
        $login = new TestUserLoginEntity($user, password_hash($password, PASSWORD_BCRYPT), 'http://avatar.url');

        $this->userRepository->expects($this->any())
            ->method('getUserByEmail')
            ->with($email)
            ->willReturn($user);

        $this->userLoginRepository->expects($this->once())
            ->method('getLoginByUser')
            ->with($user)
            ->willReturn($login);

        $this->amtgardIdpJwt->expects($this->once())
            ->method('buildAuthorizationJwt')
            ->with($user)
            ->willThrowException(new MalformedUserPolicyException(new \InvalidArgumentException('bad orn')));

        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->stringContains(MalformedUserPolicyException::USER_MESSAGE));

        $result = $this->authController->login($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertEmpty($_SESSION);
    }

    public function testLoginInvalidCredentials(): void
    {
        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['email' => 'wrong@example.com', 'password' => 'wrongpass']);

        $this->userRepository->expects($this->any())
            ->method('getUserByEmail')
            ->willReturn(null);

        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->stringContains('Invalid email or password'));

        $result = $this->authController->login($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testRegisterSuccess(): void
    {
        $email = 'new@example.com';
        $password = 'password123';

        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'firstName' => 'Jane',
                'lastName' => 'Doe',
                'email' => $email,
                'password' => $password,
                'confirmPassword' => $password
            ]);

        $this->usersExistsMock(false);

        $user = new TestUserEntity('user-2', $email, 'Jane Doe');
        $login = new TestUserLoginEntity($user, password_hash($password, PASSWORD_BCRYPT), 'http://avatar.url');

        $this->userRepository->expects($this->once())
            ->method('createLocalUser')
            ->with($email, 'Jane', 'Doe')
            ->willReturn($user);

        $this->userLoginRepository->expects($this->once())
            ->method('createLocalLogin')
            ->with($user, $password)
            ->willReturn($login);

        $this->routeParser->method('urlFor')->willReturn('/resources/profile');

        $result = $this->authController->register($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testRegisterMissingFields(): void
    {
        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'firstName' => '',
                'lastName' => 'Doe',
                'email' => 'jane@example.com',
                'password' => 'pass'
            ]);

        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->stringContains('All fields are required'));

        $result = $this->authController->register($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testRegisterInvalidEmail(): void
    {
        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'firstName' => 'Jane',
                'lastName' => 'Doe',
                'email' => 'invalid-email',
                'password' => 'pass',
                'confirmPassword' => 'pass'
            ]);

        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->stringContains('Invalid email format'));

        $result = $this->authController->register($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testRegisterMismatchedPasswords(): void
    {
        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'firstName' => 'Jane',
                'lastName' => 'Doe',
                'email' => 'jane@example.com',
                'password' => 'pass1',
                'confirmPassword' => 'pass2'
            ]);

        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->stringContains('Passwords do not match'));

        $result = $this->authController->register($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testRegisterUserExists(): void
    {
        $email = 'existing@example.com';
        $this->request->expects($this->once())
            ->method('getParsedBody')
            ->willReturn([
                'firstName' => 'Jane',
                'lastName' => 'Doe',
                'email' => $email,
                'password' => 'pass',
                'confirmPassword' => 'pass'
            ]);

        $this->usersExistsMock(true);

        $this->stream->expects($this->once())
            ->method('write')
            ->with($this->stringContains('Email already registered'));

        $result = $this->authController->register($this->request, $this->response);
        $this->assertSame($this->response, $result);
    }

    public function testLogout(): void
    {
        $_SESSION['user_id'] = 123;

        $this->routeParser->method('urlFor')->with('home')->willReturn('/');

        $this->response->expects($this->once())
            ->method('withHeader')
            ->with('Location', '/')
            ->willReturnSelf();

        $this->response->expects($this->once())
            ->method('withStatus')
            ->with(302)
            ->willReturnSelf();

        $result = $this->authController->logout($this->request, $this->response);
        $this->assertSame($this->response, $result);
        $this->assertEmpty($_SESSION);
    }

    private function usersExistsMock(bool $exists): void
    {
        $this->userRepository->expects($this->any())
            ->method('userExists')
            ->willReturn($exists);
    }
}