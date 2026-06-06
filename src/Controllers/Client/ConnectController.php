<?php
declare(strict_types=1);

namespace Amtgard\IdP\Controllers\Client;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserOrkProfileRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use Amtgard\IdP\Services\OrkLinkTokenService;
use Amtgard\IdP\Services\RegistrationService;
use Optional\Optional;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;
use Twig\Environment as TwigEnvironment;

/**
 * Browser-facing handoff landing for ORK→IDP onboarding.
 *
 * GET /auth/connect renders a tabbed Login / Register form prefilled with the
 * email from a signed link_token issued by ORK.  POST /auth/connect/login and
 * POST /auth/connect/register verify and consume the link_token, authenticate
 * or create the user, and write the user_ork_profiles row using the JWT's
 * `sub` claim (the mundane_id).  The link is keyed off the JWT, not the form
 * input, so a Discord-emailed IDP account can still link to a Gmail-emailed
 * ORK profile.
 */
class ConnectController
{
    public function __construct(
        EntityManager $entityManager,
        private TwigEnvironment $twig,
        private UserRepository $users,
        private UserLoginRepository $logins,
        private UserOrkProfileRepository $orkProfileRepository,
        private OrkLinkTokenService $tokenService,
        private RegistrationService $registrationService,
        private LoggerInterface $logger,
    ) {}

    public function showConnect(Request $request, Response $response): Response
    {
        $params    = $request->getQueryParams();
        $linkToken = $params['link_token'] ?? '';
        $email     = $params['email']      ?? '';

        if ($linkToken === '') {
            return $this->renderError($response, 'This link is invalid. Return to ORK and start over.');
        }

        // Pre-flight peek WITHOUT consuming jti: decode-only verification so we
        // can choose the default tab. The real verify+consume happens on POST.
        $peekOpt = Optional::ofNullable($this->peekTokenForRender($linkToken));
        if (!$peekOpt->isPresent()) {
            return $this->renderError($response, 'This link is invalid or expired. Return to ORK and start over.');
        }
        $peek = $peekOpt->get();

        $emailFromToken = $peek['email'] ?? $email;
        $defaultTab     = $this->users->userExists($emailFromToken) ? 'login' : 'register';

        $response->getBody()->write($this->twig->render('connect.twig', [
            'link_token' => $linkToken,
            'email'      => $emailFromToken,
            'defaultTab' => $defaultTab,
            'error'      => null,
        ]));
        return $response;
    }

    public function submitConnectLogin(Request $request, Response $response): Response
    {
        $body      = (array) $request->getParsedBody();
        $linkToken = $body['link_token'] ?? '';
        $password  = $body['password']   ?? '';

        // CR3: CSRF is enforced by CsrfMiddleware on this route (a mismatch is
        // rejected with 403 before we get here).

        // H2: peek the token (do NOT consume jti yet) so a credential failure
        // doesn't burn the single-use token.
        $claimsOpt = Optional::ofNullable($this->tokenService->peekClaims($linkToken));
        if (!$claimsOpt->isPresent()) {
            return $this->renderError($response, 'This link is invalid or expired. Return to ORK to get a fresh one.');
        }
        $claims = $claimsOpt->get();

        // CR4: authenticate against the JWT-claim email — NEVER the form body.
        $authoritativeEmail = $claims['email'];
        $user  = $this->users->getUserByEmail($authoritativeEmail);
        $login = Optional::ofNullable($user)
            ->map(fn($u) => $this->logins->getLoginByUser($u))
            ->orElse(null);
        if ($login === null || $login->getPassword() === null || !password_verify($password, $login->getPassword())) {
            return $this->renderFormError($response, $linkToken, $authoritativeEmail, 'login', 'Email or password incorrect.');
        }

        // Credentials good — NOW burn the jti so a retry can't replay.
        // consumeJti returns false on replay (already used); it can also THROW
        // on an unexpected DB error, which must not 500 — the jti was not
        // recorded, so the link is still valid and the user can retry.
        try {
            $consumed = $this->tokenService->consumeJti($claims['jti']);
        } catch (\Throwable $e) {
            $this->logger->error('ConnectController login: consumeJti failed', [
                'email'      => $authoritativeEmail,
                'mundane_id' => $claims['mundane_id'],
                'msg'        => $e->getMessage(),
            ]);
            return $this->renderError($response, 'Something went wrong on our end. Your link is still valid — please try again.');
        }
        if (!$consumed) {
            return $this->renderError($response, 'This link has already been used. Return to ORK to get a fresh one.');
        }

        try {
            $this->orkProfileRepository->linkExistingUserToMundane($user->getId(), $claims['mundane_id'], 'ork_handoff');
        } catch (\RuntimeException $e) {
            if (str_contains($e->getMessage(), 'conflict')) {
                $this->logger->warning('ConnectController login link conflict', ['msg' => $e->getMessage()]);
                return $this->renderError($response, 'That ORK profile is already linked to a different Amtgard account.');
            }
            $this->logger->error('ConnectController login: link write failed after jti consumed', [
                'idp_user_id' => $user->getUserId(),
                'mundane_id'  => $claims['mundane_id'],
                'email'       => $authoritativeEmail,
                'msg'         => $e->getMessage(),
            ]);
            return $this->renderError($response, 'Something went wrong on our end. Please try again or return to ORK to get a fresh link.');
        } catch (\Throwable $e) {
            $this->logger->error('ConnectController login: link write failed after jti consumed', [
                'idp_user_id' => $user->getUserId(),
                'mundane_id'  => $claims['mundane_id'],
                'email'       => $authoritativeEmail,
                'msg'         => $e->getMessage(),
            ]);
            return $this->renderError($response, 'Something went wrong on our end. Please try again or return to ORK to get a fresh link.');
        }

        // F6: session fixation defense — regenerate session id at auth state change.
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        if (!session_regenerate_id(true)) {
            $this->logger->warning('session_regenerate_id failed during connect handoff', ['user_id' => $user->getUserId()]);
        }
        $_SESSION['user_id'] = $user->getUserId();
        return $this->redirectBackToOrk($response, $user->getUserId(), $claims['mundane_id']);
    }

    public function submitConnectRegister(Request $request, Response $response): Response
    {
        $body      = (array) $request->getParsedBody();
        $linkToken = $body['link_token'] ?? '';
        $password  = $body['password']        ?? '';
        $confirm   = $body['confirmPassword'] ?? '';

        // CR3: CSRF is enforced by CsrfMiddleware on this route (a mismatch is
        // rejected with 403 before we get here).

        // H2: peek-only first; do not consume jti until full success.
        $claimsOpt = Optional::ofNullable($this->tokenService->peekClaims($linkToken));
        if (!$claimsOpt->isPresent()) {
            return $this->renderError($response, 'This link is invalid or expired. Return to ORK to get a fresh one.');
        }
        $claims = $claimsOpt->get();

        if ($password !== $confirm) {
            return $this->renderFormError($response, $linkToken, (string)($body['email'] ?? ''), 'register', 'Passwords do not match.');
        }

        // F2: register with the JWT-claim email, NEVER the form body. Otherwise
        // an attacker can register an IDP account under any email and have it
        // linked to the victim's mundane_id. The form email is presentation-only
        // (the input is also rendered readonly for the register tab in connect.twig).
        $authoritativeEmail = $claims['email'];
        $result = $this->registrationService->register(
            $body['firstName'] ?? '',
            $body['lastName']  ?? '',
            $authoritativeEmail,
            $password,
        );

        if (!$result['ok']) {
            return $this->renderFormError($response, $linkToken, $authoritativeEmail, 'register', $result['error']);
        }

        $user = $result['user'];

        // Registration succeeded — NOW burn the jti, then write the link.
        // consumeJti returns false on replay (already used); it can also THROW
        // on an unexpected DB error, which must not 500 — the jti was not
        // recorded, so the link is still valid and the user can retry.
        try {
            $consumed = $this->tokenService->consumeJti($claims['jti']);
        } catch (\Throwable $e) {
            $this->logger->error('ConnectController register: consumeJti failed', [
                'email'      => $authoritativeEmail,
                'mundane_id' => $claims['mundane_id'],
                'msg'        => $e->getMessage(),
            ]);
            return $this->renderError($response, 'Something went wrong on our end. Your link is still valid — please try again.');
        }
        if (!$consumed) {
            return $this->renderError($response, 'This link has already been used. Return to ORK to get a fresh one.');
        }

        // F4: jti is burned and the IDP user exists. If linkExistingUserToMundane
        // throws here, the new account is orphaned (no link) and the user cannot
        // retry with the same token. UserRepository currently exposes no clean
        // delete path; we log a clear warning so an admin can manually clean up
        // the orphan account and revoke/rotate the link. If a delete method is
        // added later, call it here inside this catch.
        try {
            $this->orkProfileRepository->linkExistingUserToMundane($user->getId(), $claims['mundane_id'], 'ork_handoff');
        } catch (\RuntimeException $e) {
            $this->logger->error('ConnectController register: orphan IDP account — link write failed after jti consumed', [
                'idp_user_id' => $user->getUserId(),
                'mundane_id'  => $claims['mundane_id'],
                'email'       => $authoritativeEmail,
                'msg'         => $e->getMessage(),
            ]);
            if (str_contains($e->getMessage(), 'conflict')) {
                return $this->renderError($response, 'That ORK profile is already linked to a different Amtgard account.');
            }
            return $this->renderError($response, 'Something went wrong on our end. Please try again or return to ORK to get a fresh link.');
        } catch (\Throwable $e) {
            // Same orphan scenario as above but for a non-RuntimeException
            // (e.g. PDOException): the jti is burned and the IDP user exists
            // but the link write failed. Log for manual cleanup and surface a
            // friendly error instead of a 500.
            $this->logger->error('ConnectController register: orphan IDP account — link write failed after jti consumed', [
                'idp_user_id' => $user->getUserId(),
                'mundane_id'  => $claims['mundane_id'],
                'email'       => $authoritativeEmail,
                'msg'         => $e->getMessage(),
            ]);
            return $this->renderError($response, 'Something went wrong on our end. Please try again or return to ORK to get a fresh link.');
        }

        // F6: session fixation defense — regenerate session id at auth state change.
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        if (!session_regenerate_id(true)) {
            $this->logger->warning('session_regenerate_id failed during connect handoff', ['user_id' => $user->getUserId()]);
        }
        $_SESSION['user_id'] = $user->getUserId();
        return $this->redirectBackToOrk($response, $user->getUserId(), $claims['mundane_id']);
    }

    /**
     * Mint a short-lived signed completion token (iss=idp, aud=ork) carrying
     * the IDP user_id (UUID) and the mundane_id, and redirect to ORK's
     * idp_link_complete endpoint so ORK can write its own ork_idp_auth row
     * and clear the dashboard banner.
     */
    private function redirectBackToOrk(Response $response, string $idpUserId, int $mundaneId): Response
    {
        // H1: prefer the new canonical env name, fall back to legacy for transition.
        $secret  = $_ENV['IDP_ORK_SHARED_SECRET'] ?? $_ENV['ORK_LINK_TOKEN_SECRET'] ?? '';
        $orkBase = $this->resolveOrkBaseUrl();

        if (strlen($secret) < 32) {
            // No secret means we can't issue the completion token; fall back to
            // plain redirect — the user is still linked on the IDP side and the
            // ORK banner will clear next time they round-trip through OAuth.
            return $response->withHeader('Location', $orkBase . '/')->withStatus(302);
        }
        $now = time();
        $b64 = fn($s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $header  = $b64(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = $b64(json_encode([
            'iss'         => 'idp',
            'aud'         => 'ork',
            'sub'         => $idpUserId,
            'mundane_id'  => $mundaneId,
            'iat'         => $now,
            'exp'         => $now + 300,
            'jti'         => bin2hex(random_bytes(18)),
        ]));
        $sig = $b64(hash_hmac('sha256', "$header.$payload", $secret, true));
        $jwt = "$header.$payload.$sig";
        $url = $orkBase . '/index.php?Route=Login/idp_link_complete&t=' . urlencode($jwt);
        return $response->withHeader('Location', $url)->withStatus(302);
    }

    /**
     * M2: validate ORK_BASE_URL — must be set, parse as an absolute URL, and
     * use http or https scheme. Returning a relative fallback would let an
     * upstream proxy host header determine the redirect target, which is
     * an open-redirect surface.
     */
    private function resolveOrkBaseUrl(): string
    {
        $raw = (string)($_ENV['ORK_BASE_URL'] ?? '');
        $raw = rtrim($raw, '/');
        if ($raw === '') {
            throw new \RuntimeException('ORK_BASE_URL is not set');
        }
        $parts = parse_url($raw);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            throw new \RuntimeException('ORK_BASE_URL is not a valid absolute URL: ' . $raw);
        }
        $scheme = strtolower($parts['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new \RuntimeException('ORK_BASE_URL scheme must be http or https: ' . $raw);
        }
        return $raw;
    }

    private function renderError(Response $response, string $message): Response
    {
        $response->getBody()->write($this->twig->render('connect.twig', [
            'link_token' => '',
            'email'      => '',
            'defaultTab' => 'login',
            'error'      => $message,
        ]));
        return $response->withStatus(400);
    }

    /**
     * Re-render the connect form preserving the link_token and the selected
     * tab, surfacing $error. Used for validation/credential failures where
     * the user should be able to retry without restarting the handoff.
     */
    private function renderFormError(Response $response, string $linkToken, string $email, string $tab, string $message): Response
    {
        $response->getBody()->write($this->twig->render('connect.twig', [
            'link_token' => $linkToken,
            'email'      => $email,
            'defaultTab' => $tab,
            'error'      => $message,
        ]));
        return $response;
    }

    /**
     * Decode the JWT without consuming jti — purely to pick the default tab on
     * GET. Distinct from $this->tokenService->peekClaims() only in that it
     * exposes nothing about jti to the caller; the controller doesn't need it
     * until POST.
     */
    private function peekTokenForRender(string $jwt): ?array
    {
        $claims = $this->tokenService->peekClaims($jwt);
        return $claims === null ? null : ['email' => $claims['email']];
    }
}
