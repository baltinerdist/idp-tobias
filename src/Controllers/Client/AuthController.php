<?php
declare(strict_types=1);

namespace Amtgard\IdP\Controllers\Client;

use Amtgard\ActiveRecordOrm\EntityManager;
use Amtgard\IdP\Models\AmtgardIdpJwt;
use Amtgard\IdP\Utility\Security\RedirectValidator;
use Amtgard\IdP\Utility\Security\ScriptAlertResponse;
use Amtgard\IdP\Persistence\Client\Repositories\UserLoginRepository;
use Amtgard\IdP\Persistence\Client\Repositories\UserRepository;
use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Provider\Google;
use Optional\Optional;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;
use Slim\Routing\RouteContext;
use Twig\Environment as TwigEnvironment;
use Wohali\OAuth2\Client\Provider\Discord;

class AuthController extends BaseAuthController
{
    private UserRepository $users;
    private UserLoginRepository $logins;
    private Google $googleProvider;
    private Facebook $facebookProvider;
    private Discord $discordProvider;
    private TwigEnvironment $twig;

    public function __construct(
        EntityManager $entityManager,
        UserRepository $users,
        UserLoginRepository $logins,
        LoggerInterface $logger,
        Google          $googleProvider,
        Facebook        $facebookProvider,
        Discord         $discordProvider,
        AmtgardIdpJwt   $amtgardIdpJwt,
        TwigEnvironment $twig
    )
    {
        parent::__construct($logger, $amtgardIdpJwt);
        $this->users = $users;
        $this->logins = $logins;
        $this->googleProvider = $googleProvider;
        $this->facebookProvider = $facebookProvider;
        $this->discordProvider = $discordProvider;
        $this->twig = $twig;
    }

    /**
     * Display the login form.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function loginForm(Request $request, Response $response): Response
    {
        $queryParams = $request->getQueryParams();
        $redirect = RedirectValidator::sanitizeOrNull($queryParams['redirect'] ?? null) ?? '';
        // Stash the validated redirect into the session so finalizeAuthorization
        // can route back to the originating /oauth/authorize after credentials
        // are validated. (Google/Discord controllers do the same, but email
        // login was missing it.)
        if ($redirect !== '') {
            $_SESSION['redirect'] = $redirect;
        }
        $response->getBody()->write($this->twig->render('login_form.twig', [
            'redirect' => $redirect,
            'jwtpublickey' => $queryParams['jwtpublickey'] ?? ''
        ]));
        return $response;
    }

    /**
     * Handle login form submission.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function login(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        $login = Optional::ofNullable($this->users->getUserByEmail($email))
            ->map(fn($user) => $this->logins->getLoginByUser($user))
            ->orElse(null);

        $isPasswordCorrect = Optional::ofNullable($login)
            ->map(fn($l) => $l->getPassword())
            ->filter(fn($p) => password_verify($password, $p))
            ->isPresent();

        // Check if user exists and password is correct
        if (!$isPasswordCorrect) {
            // Invalid credentials, redirect back to login form
            $response->getBody()->write(
                ScriptAlertResponse::alertAndRedirect('Invalid email or password', '/auth/login')
            );
            return $response;
        }

        // Set session
        return $this->finalizeAuthorization($login, $request, $response);
    }

    /**
     * Display the registration form.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function registerForm(Request $request, Response $response): Response
    {
        $response->getBody()->write($this->twig->render('register_form.twig'));
        return $response;
    }

    private function validateRequiredFields(string $firstName, string $lastName, string $email, string $password): ?string
    {
        if (empty($firstName) || empty($lastName) || empty($email) || empty($password)) {
            return ScriptAlertResponse::alertAndRedirect('All fields are required', '/auth/register');
        }
        return null;
    }

    private function validateEmailFormat(string $email): ?string
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ScriptAlertResponse::alertAndRedirect('Invalid email format', '/auth/register');
        }
        return null;
    }

    private function validatePasswordsMatch(string $password, string $confirmPassword): ?string
    {
        if ($password !== $confirmPassword) {
            return ScriptAlertResponse::alertAndRedirect('Passwords do not match', '/auth/register');
        }
        return null;
    }

    private function validateEmailIsUnique(string $email): ?string
    {
        if ($this->users->userExists($email)) {
            return ScriptAlertResponse::alertAndRedirect('Email already registered', '/auth/register');
        }
        return null;
    }

    /**
     * Handle registration form submission.
     *
     * @param Request $request
     * @param Response $response
     * @return Response
     */
    public function register(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $firstName = $data['firstName'] ?? '';
        $lastName = $data['lastName'] ?? '';
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';
        $confirmPassword = $data['confirmPassword'] ?? '';

        $validationResult = $this->validateRequiredFields($firstName, $lastName, $email, $password)
            ?? $this->validateEmailFormat($email)
            ?? $this->validatePasswordsMatch($password, $confirmPassword)
            ?? $this->validateEmailIsUnique($email);

        if ($validationResult !== null) {
            $response->getBody()->write($validationResult);
            return $response;
        }

        // Create new user
        $user = $this->users->createLocalUser($email, $firstName, $lastName);
        $login = $this->logins->createLocalLogin($user, $password);

        return $this->finalizeAuthorization($login, $request, $response);
    }

    /**
     * Logout the user. Supports OIDC RP-initiated logout style: a relying
     * party may pass ?post_logout_redirect_uri=<url> to be redirected back
     * after the IDP session is destroyed.  The redirect URI is validated
     * against the configured ORK_BASE_URL — only same-origin redirects are
     * accepted so this endpoint cannot be turned into an open redirect.
     */
    public function logout(Request $request, Response $response): Response
    {
        // Clear session
        session_unset();
        session_destroy();

        // RP-initiated logout: optionally redirect back to a trusted origin.
        $params  = $request->getQueryParams();
        $postUri = isset($params['post_logout_redirect_uri']) ? trim((string)$params['post_logout_redirect_uri']) : '';
        if ($postUri !== '' && $this->isAllowedPostLogoutUri($postUri)) {
            return $response->withHeader('Location', $postUri)->withStatus(302);
        }

        // Default: home page.
        $routeContext = RouteContext::fromRequest($request);
        $routeParser = $routeContext->getRouteParser();
        return $response
            ->withHeader('Location', $routeParser->urlFor('home'))
            ->withStatus(302);
    }

    /**
     * Validate a post-logout redirect URI against the configured ORK_BASE_URL.
     * Accepts only same-scheme-and-host-and-port matches; rejects anything
     * with auth info, fragments, or non-http(s) schemes.
     */
    private function isAllowedPostLogoutUri(string $uri): bool
    {
        $base = $_ENV['ORK_BASE_URL'] ?? '';
        if ($base === '') {
            return false;
        }
        $baseParts = parse_url($base);
        $uriParts  = parse_url($uri);
        if (!is_array($baseParts) || !is_array($uriParts)) {
            return false;
        }
        if (!in_array(($uriParts['scheme'] ?? ''), ['http', 'https'], true)) {
            return false;
        }
        if (isset($uriParts['user']) || isset($uriParts['pass'])) {
            return false;
        }
        if (($uriParts['scheme'] ?? '') !== ($baseParts['scheme'] ?? '')) {
            return false;
        }
        if (strcasecmp($uriParts['host'] ?? '', $baseParts['host'] ?? '') !== 0) {
            return false;
        }
        $basePort = $baseParts['port'] ?? (($baseParts['scheme'] ?? '') === 'https' ? 443 : 80);
        $uriPort  = $uriParts['port']  ?? (($uriParts['scheme']  ?? '') === 'https' ? 443 : 80);
        return $basePort === $uriPort;
    }
}