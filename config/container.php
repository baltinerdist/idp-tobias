<?php
declare(strict_types=1);

use Amtgard\ActiveRecordOrm\Configuration\DataAccessPolicy\UncachedDataAccessPolicy;
use Amtgard\ActiveRecordOrm\Configuration\Repository\DatabaseConfiguration;
use Amtgard\ActiveRecordOrm\Configuration\Repository\MysqlPdoProvider;
use Amtgard\ActiveRecordOrm\Entity\Policy\RepositoryPolicy;
use Amtgard\ActiveRecordOrm\Entity\Policy\UncachedPolicy;
use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\ActiveRecordOrm\Interface\DataAccessPolicy;
use Amtgard\ActiveRecordOrm\Repository\Database;
use Amtgard\IdP\Middleware\ManagementMiddleware;
use Amtgard\IdP\Models\OAuthServerConfiguration;
use Amtgard\IdP\Utility\Security\CsrfTokenManager;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use Amtgard\IdP\Services\OrkService;
use Amtgard\IdP\Persistence\Client\Repositories\UserOrkProfileRepository;
use Amtgard\IdP\Persistence\Server\Repositories\AccessTokenRepository;
use Amtgard\IdP\Persistence\Server\Repositories\AuthCodeRepository;
use Amtgard\IdP\Persistence\Server\Repositories\ClientRepository;
use Amtgard\IdP\Persistence\Server\Repositories\RefreshTokenRepository;
use Amtgard\IdP\Persistence\Server\Repositories\ScopeRepository;
use Amtgard\IdP\Persistence\Server\Repositories\UserClientAuthorizationRepository;
use Amtgard\IdP\Utility\AuthorizedClients;
use Amtgard\IdP\Utility\Constants;
use Amtgard\IdP\Utility\PubSubQueueHandle;
use Amtgard\IdP\Utility\Utility;
use Amtgard\SetQueue\DataStructure\Impl\Redis\RedisDataStructureConfig;
use Amtgard\SetQueue\DataStructure\Impl\Redis\RedisHashSetFactory;
use Amtgard\SetQueue\DataStructure\Impl\Redis\RedisRedrivableQueueFactory;
use Amtgard\SetQueue\DataStructure\SetQueue;
use Amtgard\SetQueue\PubSubQueue;
use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use Monolog\Handler\ErrorLogHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\WhatFailureGroupHandler;
use Monolog\Logger;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Twig\Environment as TwigEnvironment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;
use Wohali\OAuth2\Client\Provider\Discord;

Utility::configureIamClasses();

return [
        // Logger
    LoggerInterface::class => function () {
        $logDir = __DIR__ . '/../logs';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        $level = ($_ENV['APP_DEBUG'] ?? 'false') === 'true' ? Logger::DEBUG : Logger::ERROR;
        $logger = new Logger('app');
        $logger->pushHandler(new WhatFailureGroupHandler([
            new StreamHandler($logDir . '/app.log', $level),
            new ErrorLogHandler(level: $level),
        ]));

        return $logger;
    },

    Database::class => function (ContainerInterface $container) {
        $config = DatabaseConfiguration::fromEnvironment();
        $provider = MysqlPdoProvider::fromConfiguration($config);
        return Database::fromProvider($provider);
    },

    DataAccessPolicy::class => function (ContainerInterface $container) {
        $database = $container->get(Database::class);
        return UncachedDataAccessPolicy::builder()->database($database)->build();
    },

    UncachedDataAccessPolicy::class => function (ContainerInterface $container) {
        $database = $container->get(Database::class);
        return UncachedDataAccessPolicy::builder()->database($database)->build();
    },

    RepositoryPolicy::class => function (ContainerInterface $container) {
        return UncachedPolicy::builder()->build();
    },

    UserClientAuthorizationRepository::class => function (EntityManager $em) {
        return $em->getRepository(UserClientAuthorizationRepository::class);
    },

    EntityManager::class => function (ContainerInterface $container) {
        $em = EntityManager::builder()
            ->database($container->get(Database::class))
            ->dataAccessPolicy($container->get(DataAccessPolicy::class))
            ->repositoryPolicy($container->get(RepositoryPolicy::class))
            ->build();
        EntityManager::configure($em);
        return $em;
    },

    UserRepository::class => function (EntityManager $em) {
        return $em->getRepository(UserRepository::class);
    },

    UserRepositoryInterface::class => function (EntityManager $em) {
        return $em->getRepository(UserRepository::class);
    },

    UserLoginRepository::class => function (EntityManager $em) {
        return $em->getRepository(UserLoginRepository::class);
    },

    UserOrkProfileRepository::class => function (EntityManager $em) {
        return $em->getRepository(UserOrkProfileRepository::class);
    },

    ClientRepositoryInterface::class => function (EntityManager $em) {
        return $em->getRepository(ClientRepository::class);
    },

    ScopeRepositoryInterface::class => function (EntityManager $em) {
        return $em->getRepository(ScopeRepository::class);
    },

    AccessTokenRepositoryInterface::class => function (EntityManager $em) {
        return $em->getRepository(AccessTokenRepository::class);
    },

    AuthCodeRepositoryInterface::class => function (EntityManager $em) {
        return $em->getRepository(AuthCodeRepository::class);
    },

    ManagementMiddleware::class => function (ContainerInterface $container) {
        return new ManagementMiddleware();
    },

    // Concrete ClientRepository (the League ClientRepositoryInterface entry
    // returns the same object, but ConfidentialClientBasicAuthMiddleware needs
    // the concrete type for validateClient()). Lets that middleware autowire.
    ClientRepository::class => function (EntityManager $em) {
        return $em->getRepository(ClientRepository::class);
    },

    // ConfidentialClientBasicAuthMiddleware, OrkLinkTokenService,
    // RegistrationService and ConnectController are all resolved by autowiring.
    // The repository-backed ones (the middleware, RegistrationService,
    // ConnectController) take EntityManager as their first constructor parameter
    // so the ORM singleton is configured before their repositories resolve;
    // OrkLinkTokenService needs only Database + LoggerInterface.

    RefreshTokenRepositoryInterface::class => function (EntityManager $em) {
        return $em->getRepository(RefreshTokenRepository::class);
    },

    OAuthServerConfiguration::class => function (ContainerInterface $container) {
        return OAuthServerConfiguration::builder()
            ->clientRepository($container->get(ClientRepositoryInterface::class))
            ->scopeRepository($container->get(ScopeRepositoryInterface::class))
            ->accessTokenRepository($container->get(AccessTokenRepositoryInterface::class))
            ->authCodeRepository($container->get(AuthCodeRepositoryInterface::class))
            ->refreshTokenRepository($container->get(RefreshTokenRepositoryInterface::class))
            ->build();
    },

        // OAuth2 Authorization Server
    AuthorizationServer::class => function (ContainerInterface $container) {
        return $container->get(OAuthServerConfiguration::class)->build();
    },

        // OAuth2 Resource Server
    ResourceServer::class => function (ContainerInterface $container) {
        $publicKey = new CryptKey(
            $_ENV['OAUTH_PUBLIC_KEY'],
            null,
            false
        );

        return new ResourceServer(
            $container->get(AccessTokenRepositoryInterface::class),
            $publicKey
        );
    },

        // Google OAuth Provider
    Google::class => function () {
        return new Google([
            'clientId' => $_ENV['GOOGLE_CLIENT_ID'],
            'clientSecret' => $_ENV['GOOGLE_CLIENT_SECRET'],
            'redirectUri' => $_ENV['GOOGLE_REDIRECT_URI'],
            'scopes' => ['email', 'profile'],
        ]);
    },

        // Facebook OAuth Provider
    Facebook::class => function () {
        return new Facebook([
            'clientId' => $_ENV['FACEBOOK_CLIENT_ID'],
            'clientSecret' => $_ENV['FACEBOOK_CLIENT_SECRET'],
            'redirectUri' => $_ENV['FACEBOOK_REDIRECT_URI'],
            'graphApiVersion' => 'v12.0',
        ]);
    },

    // Discord OAuth Provider
    Discord::class => function () {
        return new Discord([
            'clientId' => $_ENV['DISCORD_CLIENT_ID'],
            'clientSecret' => $_ENV['DISCORD_CLIENT_SECRET'],
            'redirectUri' => $_ENV['DISCORD_REDIRECT_URI'],
        ]);
    },

    OrkService::class => function (ContainerInterface $container) {
        return new OrkService($container->get(LoggerInterface::class));
    },

    RedisDataStructureConfig::class => function (ContainerInterface $container) {
        $config = new RedisDataStructureConfig();
        $config->setConfig([
            'host' => '127.0.0.1',
            'port' => 6379,
        ]);
        return $config;
    },

    Redis::class => function (ContainerInterface $container) {
        $redis = new Redis();
        $config = $container->get(RedisDataStructureConfig::class);
        $redis->pconnect($config->getConfig()['host'], $config->getConfig()['port']);

        return $redis;
    },

    PubSubQueueHandle::class => function (ContainerInterface $container) {
        $queue = $container->get(SetQueue::class);
        $pubSub = $container->get(PubSubQueue::class);
        $queueName = $_ENV['REDIS_PUBLISHER_NAME'];
        $pubSub->addQueue($queueName, $queue);

        return PubSubQueueHandle::builder()->handle($queueName)->build();
    },

    SetQueue::class => function (ContainerInterface $container) {
        $hashSetFactory = new RedisHashSetFactory();
        $redrivableQueueFactory = new RedisRedrivableQueueFactory();
        $config = $container->get(RedisDataStructureConfig::class);
        $queue = new SetQueue($_ENV['REDIS_PUBLISHER_NAME'], $config, $hashSetFactory, $redrivableQueueFactory);
        return $queue;
    },

    PubSubQueue::class => function (ContainerInterface $container) {
        $redis = $container->get(Redis::class);
        if (!$redis->isConnected()) {
            throw new \Exception("Redis not connected");
        }
        $pubSub = new PubSubQueue();

        return $pubSub;
    },

        // Twig Environment
    TwigEnvironment::class => function (ContainerInterface $container) {
        $loader = new FilesystemLoader(__DIR__ . '/../templates');
        $twig = new TwigEnvironment($loader, [
            'cache' => __DIR__ . '/cache/twig',
            'auto_reload' => true,
        ]);
        // Expose the per-session CSRF token to every template as csrf_token().
        // Backed by the shared CsrfTokenManager; forms render it as a hidden
        // field (name="_csrf_token") and CsrfMiddleware validates it on POST.
        $twig->addFunction(new TwigFunction('csrf_token', fn() => CsrfTokenManager::getOrCreate()));
        return $twig;
    },

    AuthorizedClients::class => function (ContainerInterface $container) {
        return AuthorizedClients::builder()
            ->clientIds([Constants::$AMTGARD_IDP_CLIENT_ID])
            ->build();
    },

];