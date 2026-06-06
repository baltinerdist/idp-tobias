<?php
declare(strict_types=1);

use Amtgard\IdP\Controllers\Api\ApiController;
use Amtgard\IdP\Controllers\Client\AuthController;
use Amtgard\IdP\Controllers\Client\ConnectController;
use Amtgard\IdP\Controllers\Client\FacebookAuthController;
use Amtgard\IdP\Controllers\Client\GoogleAuthController;
use Amtgard\IdP\Controllers\HomeController;
use Amtgard\IdP\Controllers\Resource\LowLatencyController;
use Amtgard\IdP\Controllers\Server\OAuth2ServerController;
use Amtgard\IdP\Controllers\Management\ManagementController;
use Amtgard\IdP\Controllers\Resource\ResourcesController;
use Amtgard\IdP\Controllers\SwaggerController;
use Amtgard\IdP\Middleware\LocalAdminUserMiddleware;
use Amtgard\IdP\Middleware\LocalIdpAuthMiddleware;
use Amtgard\IdP\Middleware\ClientRestrictedAuthMiddleware;
use Amtgard\IdP\Middleware\ConfidentialClientBasicAuthMiddleware;
use Amtgard\IdP\Middleware\CsrfMiddleware;
use Amtgard\IdP\Middleware\ManagementMiddleware;
use Amtgard\IdP\Middleware\CachedJwtLocalIdpAuthMiddleware;
use Slim\App;
use Slim\Routing\RouteCollectorProxy;

return function (App $app) {
    // Home page
    $app->get('/', [HomeController::class, 'index'])->setName('home');

    // Swagger
    $app->get('/swagger', [SwaggerController::class, 'documentation'])->setName('swagger.documentation');
    $app->get('/openapi.json', [SwaggerController::class, 'openapi'])->setName('swagger.openapi');

    // Docsify
    $app->get('/docs[/]', [SwaggerController::class, 'docsify'])->setName('swagger.docsify');
    $app->get('/docs/readme.md', [SwaggerController::class, 'docsifyContent'])->setName('swagger.docsify_content');
    $app->get('/docs/README.md', [SwaggerController::class, 'docsifyContent'])->setName('swagger.docsify_content_upper');

    $app->group('/api', function (RouteCollectorProxy $group) {
        $group->post('/is_authorized', [ApiController::class, 'isAuthorized'])->setName('api.is_authorized');
    });

    $app->group('/resources', function (RouteCollectorProxy $group) {
        $group->get('/validate', [LowLatencyController::class, 'validate'])
            ->setName('resources.validate');

        // UserRepository info endpoint (protected by access access_token)
        $group->get('/userinfo', [ResourcesController::class, 'userInfo'])
            ->add(CachedJwtLocalIdpAuthMiddleware::class)
            ->setName('resources.userinfo');

        $group->get('/profile', [ResourcesController::class, 'profile'])
            ->add(LocalIdpAuthMiddleware::class)
            ->setName('resources.profile');

        $group->get('/authorizations', [ResourcesController::class, 'authorizations'])
            ->add(ClientRestrictedAuthMiddleware::class)
            ->setName('resources.authorizations');

        $group->post('/profile/link-ork', [ResourcesController::class, 'linkOrkAccount'])
            ->add(CsrfMiddleware::class)
            ->add(ClientRestrictedAuthMiddleware::class)
            ->setName('resources.profile.link_ork');

        $group->post('/profile/refresh-ork', [ResourcesController::class, 'refreshOrkAccount'])
            ->add(CsrfMiddleware::class)
            ->add(ClientRestrictedAuthMiddleware::class)
            ->setName('resources.profile.refresh_ork');

        $group->post('/profile/revoke', [ResourcesController::class, 'revokeAuthorization'])
            ->add(CsrfMiddleware::class)
            ->add(ClientRestrictedAuthMiddleware::class)
            ->setName('resources.profile.revoke');

        // Server-to-server: ORK calls this to mirror a successful local link write
        // into the IDP. Basic auth against the confidential-client credentials.
        $group->post('/link-ork-profile', [ResourcesController::class, 'linkOrkProfile'])
            ->add(ConfidentialClientBasicAuthMiddleware::class)
            ->setName('resources.link_ork_profile');
            
        $group->get('/jwt', [ResourcesController::class, 'getJwt'])
            ->add(LocalIdpAuthMiddleware::class)
            ->setName('resources.jwt');
    });

    // Authentication routes
    $app->group('/auth', function (RouteCollectorProxy $group) {
        // Login form
        $group->get('/login', [AuthController::class, 'loginForm'])->setName('auth.login');
        $group->post('/login', [AuthController::class, 'login'])->add(CsrfMiddleware::class);

        // Registration form
        $group->get('/register', [AuthController::class, 'registerForm'])->setName('auth.register');
        $group->post('/register', [AuthController::class, 'register'])->add(CsrfMiddleware::class);

        // Logout
        $group->get('/logout', [AuthController::class, 'logout'])->setName('auth.logout');

        // Social login routes
        $group->get('/google', [GoogleAuthController::class, 'redirectToGoogle'])->setName('auth.google');
        $group->get('/google/callback', [GoogleAuthController::class, 'handleGoogleCallback'])->setName('auth.google.callback');

        $group->get('/facebook', [FacebookAuthController::class, 'redirectToFacebook'])->setName('auth.facebook');
        $group->get('/facebook/callback', [FacebookAuthController::class, 'handleFacebookCallback'])->setName('auth.facebook.callback');

        $group->get('/discord', [\Amtgard\IdP\Controllers\Client\DiscordAuthController::class, 'redirectToDiscord'])->setName('auth.discord');
        $group->get('/discord/callback', [\Amtgard\IdP\Controllers\Client\DiscordAuthController::class, 'handleDiscordCallback'])->setName('auth.discord.callback');

        // ORK→IDP onboarding handoff. ORK signs a short-lived JWT and redirects
        // the user here; we log them in or register them and write the link.
        $group->get('/connect', [ConnectController::class, 'showConnect'])->setName('auth.connect.show');
        $group->post('/connect/login', [ConnectController::class, 'submitConnectLogin'])->add(CsrfMiddleware::class)->setName('auth.connect.login');
        $group->post('/connect/register', [ConnectController::class, 'submitConnectRegister'])->add(CsrfMiddleware::class)->setName('auth.connect.register');
    });

    // Management routes
    $app->group('/management', function (RouteCollectorProxy $group) {
        $group->get('/cleantokens', [ManagementController::class, 'cleanTokens'])
            ->add(ManagementMiddleware::class)
            ->setName('management.cleantokens');

        $group->get('/clients', [ManagementController::class, 'listClients'])
            ->add(LocalIdpAuthMiddleware::class)
            ->add(LocalAdminUserMiddleware::class)
            ->setName('management.clients');
            
        $group->post('/clients', [ManagementController::class, 'createClient'])
            ->add(CsrfMiddleware::class)
            ->add(LocalIdpAuthMiddleware::class)
            ->add(LocalAdminUserMiddleware::class)
            ->setName('management.clients.create');

        $group->post('/clients/{id}', [ManagementController::class, 'updateClient'])
            ->add(CsrfMiddleware::class)
            ->add(LocalIdpAuthMiddleware::class)
            ->add(LocalAdminUserMiddleware::class)
            ->setName('management.clients.update');
    });

    // OAuth2 server routes
    $app->group('/oauth', function (RouteCollectorProxy $group) {
        // Authorization endpoint
        $group->get('/authorize', [OAuth2ServerController::class, 'authorize'])->setName('oauth.authorize');
        $group->post('/authorize', [OAuth2ServerController::class, 'authorizePost']);

        // access_token endpoint
        $group->post('/token', [OAuth2ServerController::class, 'token'])->setName('oauth.token');

        // access_token endpoint
        $group->map(['GET', 'POST'], '/approve', [OAuth2ServerController::class, 'approve'])->add(CsrfMiddleware::class)->setName('oauth.approve');

    });
};