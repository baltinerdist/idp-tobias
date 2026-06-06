<?php
declare(strict_types=1);

namespace Amtgard\IdP\Services;

use Amtgard\ActiveRecordOrm\Repository\Database;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Psr\Log\LoggerInterface;

/**
 * Verifies short-lived HS256 JWTs minted by ORK3 for the /auth/connect handoff.
 * Records the jti in link_token_jti to make tokens single-use even within their
 * 15-minute validity window.
 */
class OrkLinkTokenService
{
    public function __construct(
        private Database $database,
        private LoggerInterface $logger,
    ) {}

    /**
     * Resolve and validate the HS256 shared secret at the point of use rather
     * than at container-build time, so a misconfigured secret surfaces as a
     * clear runtime error from this service instead of an opaque DI failure.
     *
     * Canonical env var is IDP_ORK_SHARED_SECRET (matches ORK's resolver);
     * ORK_LINK_TOKEN_SECRET is retained as a transition-period fallback.
     */
    private function sharedSecret(): string
    {
        $secret = $_ENV['IDP_ORK_SHARED_SECRET'] ?? $_ENV['ORK_LINK_TOKEN_SECRET'] ?? '';
        if (strlen($secret) < 32) {
            throw new \RuntimeException('IDP_ORK_SHARED_SECRET (or legacy ORK_LINK_TOKEN_SECRET) is unset or shorter than 32 chars');
        }
        return $secret;
    }

    /**
     * Decode + claim-validate WITHOUT consuming the jti. Use this when the
     * caller still needs to validate user-supplied prerequisites (password,
     * registration data) before burning the single-use token.
     *
     * @return array{mundane_id: int, email: string, jti: string}|null
     */
    public function peekClaims(string $jwt): ?array
    {
        JWT::$leeway = 30;
        try {
            $decoded = JWT::decode($jwt, new Key($this->sharedSecret(), 'HS256'));
        } catch (ExpiredException $e) {
            $this->logger->info('OrkLinkToken expired', ['msg' => $e->getMessage()]);
            return null;
        } catch (SignatureInvalidException $e) {
            $this->logger->warning('OrkLinkToken bad signature', ['msg' => $e->getMessage()]);
            return null;
        } catch (\Throwable $e) {
            $this->logger->info('OrkLinkToken decode error', ['msg' => $e->getMessage()]);
            return null;
        }

        if (($decoded->iss ?? null) !== 'ork') {
            $this->logger->warning('OrkLinkToken wrong iss', ['iss' => $decoded->iss ?? 'null']);
            return null;
        }
        if (($decoded->aud ?? null) !== 'idp') {
            $this->logger->warning('OrkLinkToken wrong aud', ['aud' => $decoded->aud ?? 'null']);
            return null;
        }
        if (!isset($decoded->sub) || !ctype_digit((string)$decoded->sub) || (int)$decoded->sub <= 0) {
            $this->logger->warning('OrkLinkToken bad sub', ['sub' => (string)($decoded->sub ?? 'null')]);
            return null;
        }
        if (empty($decoded->jti) || empty($decoded->email)) {
            $this->logger->warning('OrkLinkToken missing required claim');
            return null;
        }

        return [
            'mundane_id' => (int)$decoded->sub,
            'email'      => (string)$decoded->email,
            'jti'        => (string)$decoded->jti,
        ];
    }

    /**
     * Idempotently record the jti. Returns false if already seen (replay).
     */
    public function consumeJti(string $jti): bool
    {
        try {
            $this->database->clear();
            $this->database->__set('jti', $jti);
            $this->database->execute("INSERT INTO link_token_jti (jti, seen_at) VALUES (:jti, NOW())");
            return true;
        } catch (\PDOException $e) {
            if ($e->getCode() === '23000' || str_contains($e->getMessage(), 'Duplicate')) {
                $this->logger->warning('OrkLinkToken replay', ['jti' => $jti]);
                return false;
            }
            throw $e;
        }
    }

    /**
     * Best-effort cleanup of consumed jti rows older than 1 hour. Safe to call
     * from a periodic management endpoint or cron.
     */
    public function cleanExpiredJti(): void
    {
        try {
            $this->database->clear();
            $this->database->execute("DELETE FROM link_token_jti WHERE seen_at < (NOW() - INTERVAL 1 HOUR)");
        } catch (\Throwable $e) {
            $this->logger->warning('cleanExpiredJti failed', ['msg' => $e->getMessage()]);
        }
    }
}
