<?php

namespace Amtgard\IdP\Middleware;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Models\AllowedLinkOrkProfileClientIds;
use Amtgard\IdP\Persistence\Server\Repositories\ClientRepository;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Psr\Log\LoggerInterface;
use Slim\Exception\HttpUnauthorizedException;

/**
 * Server-to-server gate: HTTP Basic auth against the `clients` table, with an
 * env-driven allow-list of which confidential clients may hit this endpoint.
 *
 * Used by POST /resources/link-ork-profile so ORK can assert link updates
 * without first round-tripping through the OAuth code+token dance.
 *
 * EntityManager is the first parameter purely so autowiring configures the ORM
 * singleton before ClientRepository resolves; it is not used directly here.
 */
class ConfidentialClientBasicAuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        EntityManager $entityManager,
        private ClientRepository $clientRepository,
        private AllowedLinkOrkProfileClientIds $allowedClientIds,
        private LoggerInterface $logger,
    ) {}

    public function process(Request $request, RequestHandler $handler): Response
    {
        $header = $request->getHeaderLine('Authorization');
        if (!preg_match('/^Basic\s+(\S+)$/i', $header, $matches)) {
            $this->logger->info('ConfidentialClientBasic: missing or non-Basic Authorization header');
            throw new HttpUnauthorizedException($request, 'Confidential client credentials required.');
        }

        $decoded = base64_decode($matches[1], true);
        if ($decoded === false || !str_contains($decoded, ':')) {
            $this->logger->info('ConfidentialClientBasic: malformed credentials');
            throw new HttpUnauthorizedException($request, 'Malformed credentials.');
        }

        [$clientId, $clientSecret] = explode(':', $decoded, 2);

        if (!$this->allowedClientIds->contains($clientId)) {
            $this->logger->warning('ConfidentialClientBasic: client_id not in allow-list', ['client_id' => $clientId]);
            throw new HttpUnauthorizedException($request, 'Client not authorized for this endpoint.');
        }

        if (!$this->clientRepository->validateClient($clientId, $clientSecret, 'confidential_basic')) {
            $this->logger->warning('ConfidentialClientBasic: bad credentials for allow-listed client', ['client_id' => $clientId]);
            throw new HttpUnauthorizedException($request, 'Invalid client credentials.');
        }

        return $handler->handle($request);
    }
}
