<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Models;

use Amtgard\ActiveRecordOrm\Interface\EntityInterface;
use Amtgard\IdP\Models\AmtgardIdpJwt;
use Amtgard\IdP\Models\OAuthServerConfiguration;
use Amtgard\IdP\Models\Orn\IdpClaim;
use Amtgard\IdP\Persistence\Common\Repositories\JwtChallenge;
use Amtgard\IdP\Persistence\Common\Repositories\UserPolicy;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use PHPUnit\Framework\TestCase;

class ModelsTest extends TestCase
{
    protected function setUp(): void
    {
        $devKeysDir = dirname(__DIR__, 2) . '/dev-keys';
        if (!file_exists('/tmp/private.key') && file_exists($devKeysDir . '/private.key')) {
            @copy($devKeysDir . '/private.key', '/tmp/private.key');
        }
        if (!file_exists('/tmp/public.key') && file_exists($devKeysDir . '/public.key')) {
            @copy($devKeysDir . '/public.key', '/tmp/public.key');
        }
        $_ENV['OAUTH_PRIVATE_KEY'] = '/tmp/private.key';
        $_ENV['OAUTH_PUBLIC_KEY'] = '/tmp/public.key';
        $_ENV['AUTH_SERVER_DEFUSE_KEY'] = str_repeat('a', 64);
        $_ENV['OAUTH_AUTH_TOKEN_TTL'] = 'PT10M';
        $_ENV['OAUTH_REFRESH_TOKEN_TTL'] = 'P1M';
        $_ENV['OAUTH_ACCESS_TOKEN_TTL'] = 'PT1H';
    }

    public function testAmtgardIdpJwt(): void
    {
        $userPolicy = $this->createMock(UserPolicy::class);
        $userPolicyPolicy = $this->createMock(\Amtgard\IAM\Allowance\Policy::class);
        $userPolicyPolicy->method('toJson')->willReturn('{"foo":"bar"}');
        $userPolicy->method('getUserPolicy')->willReturn($userPolicyPolicy);

        $jwtChallenge = $this->createMock(JwtChallenge::class);
        $jwtChallenge->method('createChallenge')->willReturn('challenge123');

        $user = $this->createMock(EntityInterface::class);
        $user->userId = 'user-123';
        $user->orkUserId = 456;
        $user->username = 'testuser';
        $user->email = 'test@example.com';

        @session_start();
        $_SESSION['client_id'] = 'client-123';

        $idpJwt = new AmtgardIdpJwt($userPolicy, $jwtChallenge);
        $jwtString = $idpJwt->buildAuthorizationJwt($user);
        
        $this->assertIsString($jwtString);

        // test validate
        $jwtChallenge->expects($this->once())
            ->method('validateChallenge')
            ->with('some-jwt-string')
            ->willReturn(true);

        $this->assertTrue($idpJwt->validateJwtChallenge('some-jwt-string'));
    }

    public function testOAuthServerConfiguration(): void
    {
        $clientRepo = $this->createMock(ClientRepositoryInterface::class);
        $scopeRepo = $this->createMock(ScopeRepositoryInterface::class);
        $accessTokenRepo = $this->createMock(AccessTokenRepositoryInterface::class);
        $authCodeRepo = $this->createMock(AuthCodeRepositoryInterface::class);
        $refreshTokenRepo = $this->createMock(RefreshTokenRepositoryInterface::class);

        $config = OAuthServerConfiguration::builder()
            ->clientRepository($clientRepo)
            ->scopeRepository($scopeRepo)
            ->accessTokenRepository($accessTokenRepo)
            ->authCodeRepository($authCodeRepo)
            ->refreshTokenRepository($refreshTokenRepo)
            ->build();

        $server = $config->build();
        $this->assertInstanceOf(\League\OAuth2\Server\AuthorizationServer::class, $server);
    }

    public function testIdpClaim(): void
    {
        \Amtgard\IAM\ORN\OrnClassMap::$ORN_CLASS_MAP[\Amtgard\IAM\OrkService::Idp->value] = IdpClaim::class;
        $claim = \Amtgard\IAM\ClaimFactory::createOrn("Idp:0::::IDP/EditClient");
        $this->assertInstanceOf(IdpClaim::class, $claim);
    }
}
