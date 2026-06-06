<?php
declare(strict_types=1);

use Amtgard\IdP\Middleware\SessionMiddleware;
use Amtgard\IdP\Middleware\JsonBodyParserMiddleware;
use Psr\Log\LoggerInterface;
use Slim\App;
use Slim\Middleware\MethodOverrideMiddleware;

return function (App $app) {
    // Parse json, form data and xml
    $app->addBodyParsingMiddleware();

    // Add the JSON body parser middleware
    $app->add(new JsonBodyParserMiddleware());



    // Add session middleware
    $app->add(new SessionMiddleware());

    // Add method override middleware to support PUT, DELETE, etc. with a form
    $app->add(new MethodOverrideMiddleware());

    // Add CORS middleware
    // Added last so it runs first (LIFO), handling OPTIONS requests before other middleware/routing
    $app->add(new \Amtgard\IdP\Middleware\CorsMiddleware());

    // Log exceptions to Monolog (logs/app.log); display details only when APP_DEBUG=true
    $displayErrorDetails = ($_ENV['APP_DEBUG'] ?? 'false') === 'true';
    $logger = $app->getContainer()->get(LoggerInterface::class);

    return $app->addErrorMiddleware($displayErrorDetails, true, true, $logger);
};
