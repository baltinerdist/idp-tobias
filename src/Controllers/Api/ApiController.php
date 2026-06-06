<?php
declare(strict_types=1);

namespace Amtgard\IdP\Controllers\Api;

use Amtgard\IAM\Allowance\Policy;
use Amtgard\IAM\ClaimFactory;
use Amtgard\IAM\OrkService;
use Amtgard\IAM\PolicyFactory;
use Amtgard\IdP\Models\Orn\IdpRequirement;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class ApiController
{
    public function isAuthorized(Request $request, Response $response): Response
    {
        $body = $request->getParsedBody();
        $policyJson = $body['policy'] ?? '[]';
        $requirementString = $body['requirement'] ?? '';

        $policy = PolicyFactory::fromOrn(json_decode($policyJson, true));
        $requirement = new \Amtgard\IdP\Models\Orn\IdpRequirement(\Amtgard\IAM\OrkService::Idp, $requirementString);

        $isAuthorized = $policy->isAuthorized($requirement);

        $response->getBody()->write(json_encode(['is_authorized' => $isAuthorized]));
        return $response->withHeader('Content-Type', 'application/json');
    }
}
