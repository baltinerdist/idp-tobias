<?php
declare(strict_types=1);

namespace Amtgard\IdP\Controllers\Resource;

use OpenApi\Attributes as OA;

#[OA\Info(
    title: "Amtgard Identity Provider API",
    version: "1.0.0",
    description: "API endpoints for the Amtgard Identity Provider (IdP) server, facilitating authentication and profile retrieval for Amtgard services."
)]
#[OA\Server(
    url: "/",
    description: "Current Host Server"
)]
#[OA\SecurityScheme(
    securityScheme: "bearerAuth",
    type: "http",
    name: "Authorization",
    in: "header",
    scheme: "bearer",
    bearerFormat: "JWT"
)]
class OpenApi
{
    // This class serves as a container for global OpenAPI annotations scanned by swagger-php.
}
