<?php
declare(strict_types=1);

namespace Amtgard\IdP\Middleware;

use Amtgard\IdP\Utility\Security\CsrfTokenManager;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Psr\Log\LoggerInterface;
use Slim\Exception\HttpForbiddenException;

/**
 * Synchronizer-token CSRF guard for browser-facing form POSTs. Add this to any
 * state-changing route that is driven by a session-authenticated HTML form.
 *
 * Validation is delegated to the shared {@see CsrfTokenManager}; the token is
 * accepted from the CsrfTokenManager::TOKEN_FIELD form field or the
 * X-CSRF-Token header. Safe methods (GET/HEAD/OPTIONS) pass straight through,
 * so it is safe to attach to routes mapped to both GET and POST.
 *
 * NOT for machine-to-machine endpoints (OAuth token, server-to-server basic
 * auth, JSON APIs) — those authenticate per request and carry no session.
 */
class CsrfMiddleware implements MiddlewareInterface
{
    private const UNSAFE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    public function __construct(
        private LoggerInterface $logger,
    ) {}

    public function process(Request $request, RequestHandler $handler): Response
    {
        if (in_array(strtoupper($request->getMethod()), self::UNSAFE_METHODS, true)) {
            $body  = (array) $request->getParsedBody();
            $token = $request->getHeaderLine('X-CSRF-Token');
            if ($token === '') {
                $field = $body[CsrfTokenManager::TOKEN_FIELD] ?? null;
                $token = is_string($field) ? $field : '';
            }

            if (!CsrfTokenManager::validate($token)) {
                $this->logger->warning('CSRF token validation failed', [
                    'path'   => $request->getUri()->getPath(),
                    'method' => $request->getMethod(),
                ]);
                throw new HttpForbiddenException($request, 'Invalid or missing CSRF token. Please reload the page and try again.');
            }
        }

        return $handler->handle($request);
    }
}
