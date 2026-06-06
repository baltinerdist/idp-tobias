<?php
declare(strict_types=1);

namespace Amtgard\IdP\Controllers;

use OpenApi\Generator;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Twig\Environment as TwigEnvironment;

class SwaggerController
{
    private TwigEnvironment $twig;

    public function __construct(TwigEnvironment $twig)
    {
        $this->twig = $twig;
    }

    public function documentation(Request $request, Response $response): Response
    {
        $response->getBody()->write($this->twig->render('swagger.twig'));
        return $response;
    }

    public function openapi(Request $request, Response $response): Response
    {
        $openapi = (new Generator())->generate([
            __DIR__ . '/Server',
            __DIR__ . '/Resource'
        ]);
        $response->getBody()->write($openapi->toJson());
        return $response->withHeader('Content-Type', 'application/json');
    }

    public function docsify(Request $request, Response $response): Response
    {
        $response->getBody()->write($this->twig->render('docsify.twig'));
        return $response;
    }

    public function docsifyContent(Request $request, Response $response): Response
    {
        $filePath = dirname(__DIR__, 2) . '/templates/api.md';
        if (!file_exists($filePath)) {
            $response->getBody()->write("Documentation not found.");
            return $response->withStatus(404)->withHeader('Content-Type', 'text/plain');
        }
        $response->getBody()->write(file_get_contents($filePath));
        return $response->withHeader('Content-Type', 'text/markdown');
    }
}
