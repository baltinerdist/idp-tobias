<?php

declare(strict_types=1);

use DI\Bridge\Slim\Bridge;
use DI\ContainerBuilder;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

// Load environment variables from the gitignored .env file. Keeping a single
// loaded env file (never committed) avoids the risk of secrets leaking via a
// checked-in dev env. safeLoad() doesn't error when the file is missing.
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

$debug = ($_ENV['APP_DEBUG'] ?? 'false') === 'true';
error_reporting($debug ? E_ALL : (E_ERROR | E_PARSE));
ini_set('display_errors', $debug ? '1' : '0');

// Set up dependency injection container
$containerBuilder = new ContainerBuilder();

// Add container definitions
$containerBuilder->addDefinitions(__DIR__ . '/../config/container.php');

$containerBuilder->useAutowiring(true);

// Build the container
$container = $containerBuilder->build();

// Create the app
$app = Bridge::create($container);

// Register middleware
(require __DIR__ . '/../config/middleware.php')($app);

// Register routes
(require __DIR__ . '/../config/routes.php')($app);

// Run the app
$app->run();
