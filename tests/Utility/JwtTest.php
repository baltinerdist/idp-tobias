<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Utility;

use Amtgard\IdP\Utility\Jwt;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class JwtTest extends TestCase
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
    }

    public function testGetBearerJwt(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('Bearer my-token-123');

        $this->assertSame('my-token-123', Jwt::getBearerJwt($request));

        $request2 = $this->createMock(ServerRequestInterface::class);
        $request2->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('InvalidHeader');

        $this->assertNull(Jwt::getBearerJwt($request2));
    }

    public function testParseJwt(): void
    {
        // A dummy JWT string: header.payload.signature
        // payload = {"sub":"123","aud":"test-aud","iss":"test-iss","exp":9999999999}
        // base64url of payload is eyJzdWIiOiIxMjMiLCJhdWQiOiJ0ZXN0LWF1ZCIsImlzcyI6InRlc3QtaXNzIiwiZXhwIjo5OTk5OTk5OTk5fQ
        $payload = 'eyJzdWIiOiIxMjMiLCJhdWQiOiJ0ZXN0LWF1ZCIsImlzcyI6InRlc3QtaXNzIiwiZXhwIjo5OTk5OTk5OTk5fQ';
        $jwt = "header.{$payload}.signature";

        $parsed = Jwt::parseJwt($jwt);
        $this->assertIsArray($parsed);
        $this->assertSame('test-aud', $parsed['aud']);

        $parsedWithBearer = Jwt::parseJwt("Bearer {$jwt}");
        $this->assertIsArray($parsedWithBearer);
        $this->assertSame('test-iss', $parsedWithBearer['iss']);

        $invalidJwt = 'invalid-jwt-without-three-parts';
        $this->assertNull(Jwt::parseJwt($invalidJwt));
    }

    public function testValidateJwtAudienceMismatch(): void
    {
        $payload1 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5fQ'; // aud-1, iss-1, exp-9999999999
        $payload2 = 'eyJhdWQiOiJhdWQtMiIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5fQ'; // aud-2, iss-1

        $jwt1 = "header.{$payload1}.signature";
        $jwt2 = "header.{$payload2}.signature";

        $this->assertFalse(Jwt::validateJwt($jwt1, $jwt2));
    }

    public function testValidateJwtIssuerMismatch(): void
    {
        $payload1 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5fQ'; // aud-1, iss-1, exp-9999999999
        $payload2 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0yIiwiZXhwIjo5OTk5OTk5OTk5fQ'; // aud-1, iss-2

        $jwt1 = "header.{$payload1}.signature";
        $jwt2 = "header.{$payload2}.signature";

        $this->assertFalse(Jwt::validateJwt($jwt1, $jwt2));
    }

    public function testValidateJwtExpiredOrMissingExp(): void
    {
        // exp = 1000 (past)
        $payload1 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjoxMDAwfQ';
        $jwt1 = "header.{$payload1}.signature";

        $payload2 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5fQ';
        $jwt2 = "header.{$payload2}.signature";

        // Expired challenge
        $this->assertFalse(Jwt::validateJwt($jwt1, $jwt2));

        // Missing exp challenge
        $payloadNoExp = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xfQ';
        $jwtNoExp = "header.{$payloadNoExp}.signature";
        $this->assertFalse(Jwt::validateJwt($jwtNoExp, $jwt2));
    }

    public function testValidateJwtPolicyMismatch(): void
    {
        // Challenge with policy, user data with null policy
        $payload1 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5LCJwb2xpY3kiOiJbXXlifQ';
        $payload2 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5fQ';

        $jwt1 = "header.{$payload1}.signature";
        $jwt2 = "header.{$payload2}.signature";

        $this->assertFalse(Jwt::validateJwt($jwt1, $jwt2));
    }

    public function testValidateJwtSuccessWithMatchingPolicies(): void
    {
        // Same policy JSON
        $payload1 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5LCJwb2xpY3kiOiJbXXkifQ';
        $jwt1 = "header.{$payload1}.signature";

        $this->assertTrue(Jwt::validateJwt($jwt1, $jwt1));
    }

    public function testValidateJwtOnePolicyNull(): void
    {
        // Challenge policy is null, user policy is not null
        $payload1 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5fQ';
        $payload2 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5LCJwb2xpY3kiOiJbXXkifQ';

        $jwt1 = "header.{$payload1}.signature";
        $jwt2 = "header.{$payload2}.signature";

        $this->assertFalse(Jwt::validateJwt($jwt1, $jwt2));
    }

    public function testValidateJwtDifferentPoliciesNotMatching(): void
    {
        // Policy JSON is different (one allows EditClient, one allows something else)
        // {"aud":"aud-1","iss":"iss-1","exp":9999999999,"policy":"[\"Idp:0::::IDP/EditClient\"]"}
        $payload1 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5LCJwb2xpY3kiOiJbXCJJZHA6MDo6OjpJRFAvRWRpdENsaWVudFwiXSJ9';

        // {"aud":"aud-1","iss":"iss-1","exp":9999999999,"policy":"[\"Idp:0::::IDP/EditIdentity\"]"}
        $payload2 = 'eyJhdWQiOiJhdWQtMSIsImlzcyI6Imlzcy0xIiwiZXhwIjo5OTk5OTk5OTk5LCJwb2xpY3kiOiJbXCJJZHA6MDo6OjpJRFAvRWRpdElkZW50aXR5XCJdIn0';

        $jwt1 = "header.{$payload1}.signature";
        $jwt2 = "header.{$payload2}.signature";

        $this->assertFalse(Jwt::validateJwt($jwt1, $jwt2));
    }

    public function testValidateJwtInvalidTokens(): void
    {
        $this->assertFalse(Jwt::validateJwt('invalid', 'invalid'));
    }

    public function testValidateJwtSignatureAndRequest(): void
    {
        if (!file_exists('/tmp/private.key') || !file_exists('/tmp/public.key')) {
            $this->markTestSkipped('Keys are missing');
        }

        $clock = new \Lcobucci\Clock\SystemClock(new \DateTimeZone("UTC"));
        $config = \Lcobucci\JWT\Configuration::forAsymmetricSigner(
            new \Lcobucci\JWT\Signer\Rsa\Sha256(),
            \Lcobucci\JWT\Signer\Key\InMemory::file('/tmp/private.key'),
            \Lcobucci\JWT\Signer\Key\InMemory::file('/tmp/public.key')
        );

        $now = $clock->now();
        $token = $config->builder()
            ->issuedBy('http://localhost')
            ->permittedFor('client-1')
            ->expiresAt($now->modify('+1 hour'))
            ->getToken($config->signer(), $config->signingKey());

        $jwtStr = $token->toString();

        $this->assertSame($jwtStr, Jwt::validateJwtSignature($jwtStr));

        // Invalid signature / modified JWT
        $this->assertNull(Jwt::validateJwtSignature($jwtStr . 'invalid'));

        // Test validateJwtRequest
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn("Bearer {$jwtStr}");

        $this->assertSame($jwtStr, Jwt::validateJwtRequest($request));

        // Test validateJwtRequest with missing header
        $request2 = $this->createMock(ServerRequestInterface::class);
        $request2->expects($this->once())
            ->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn('');
        $this->assertNull(Jwt::validateJwtRequest($request2));
    }
}
