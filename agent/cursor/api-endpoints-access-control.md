# Amtgard IDP — API Endpoints & Access Control

**Service:** Amtgard Identity Provider (`amtgard-bastion-idp`)  
**Date:** 2026-06-05  
**Base URL:** `https://idp.amtgard.com` (dev: `http://localhost:37080`)

This document describes every routed endpoint, its intended use case, current access control, and recommended access posture.

---

## Access control mechanisms (reference)

| Mechanism | How it works |
|-----------|--------------|
| **None** | No middleware; anyone on the internet can call the endpoint. |
| **Session** | PHP session cookie (`SessionMiddleware`). User must have logged in via `/auth/*`. |
| **OAuth2 Resource Server** | `Authorization: Bearer <access_token>` validated by League OAuth2 Server (signature, expiry, revocation). |
| **IDP JWT (Bearer)** | RS256-signed JWT in `Authorization: Bearer`. Signature validated against `OAUTH_PUBLIC_KEY`. Used by `CachedJwtLocalIdpAuthMiddleware` and `ClientRestrictedAuthMiddleware`. |
| **Authorized client allowlist** | JWT `aud` (client ID) or session `client_id` must be in `AuthorizedClients` — currently only `amtgard-idp-client-id`. |
| **Redis validation cache** | After first successful token validation, user/client cached in Redis for fast-path on subsequent requests. |
| **IAM admin policy** | `UserAuthority::isAdmin()` — user must satisfy ORN requirement `Idp:0::::IDP/EditClient`. |
| **Management key** | `GET ?key=` must match `MANAGEMENT_KEY` env var (min 32 chars). |
| **OAuth2 Authorization Server** | League OAuth2 Server validates client registration, redirect URIs, PKCE, scopes (`email`, `profile`), and issues tokens. |
| **Social OAuth state** | Google/Facebook/Discord callbacks validate `state` via `OAuth2StateManager`. |

---

## Legend

| Column | Meaning |
|--------|---------|
| **Should be** | Recommended exposure model |
| **Public** | Unauthenticated internet-facing (by design) |
| **Authenticated user** | End user must be logged in |
| **OAuth client** | Registered OAuth2 client with valid token/credentials |
| **Service / internal** | Backend services only; not general internet |
| **Admin** | Privileged operators only |

---

## 1. Public web (HTML)

### `GET /`

| | |
|---|---|
| **Use case** | Marketing/landing page; shows login state and avatar if session exists. |
| **Current** | **Public** — no middleware. Reads session opportunistically for display. |
| **Should be** | **Public** |

---

## 2. Documentation

### `GET /swagger`

| | |
|---|---|
| **Use case** | Swagger UI for exploring documented JSON API endpoints. |
| **Current** | **Public** |
| **Should be** | **Public** in dev; **restricted** in production (IP allowlist, auth, or disable). Exposes API surface. |

### `GET /openapi.json`

| | |
|---|---|
| **Use case** | Machine-readable OpenAPI spec (generated from `ResourcesController`, `LowLatencyController` annotations). |
| **Current** | **Public** |
| **Should be** | Same as `/swagger` — public in dev, restricted in prod. |

### `GET /docs`, `GET /docs/readme.md`, `GET /docs/README.md`

| | |
|---|---|
| **Use case** | Docsify developer documentation UI and markdown content. |
| **Current** | **Public** |
| **Should be** | **Public** in dev; **restricted** in prod. |

---

## 3. Policy API

### `POST /api/is_authorized`

| | |
|---|---|
| **Use case** | **Authorization decision service.** Other Amtgard apps/services POST a user's IAM policy (ORN JSON) and a requirement string; IDP returns `{ "is_authorized": true/false }`. This is the policy engine — not a user-data endpoint. |
| **Request body** | `policy` (JSON array), `requirement` (string, e.g. IAM requirement path) |
| **Current** | **Public** — no middleware, no auth. |
| **Should be** | **Service / internal** — must remain callable by backend services without end-user login, but should **not** be wide-open internet anonymous. Recommendations: |
| | • Network restriction (private VPC, service mesh) |
| | • Optional service API key or mTLS between callers |
| | • Rate limiting + input size limits on `policy` JSON |
| | • Audit logging |
| | **Do not** require end-user session/OAuth — that would break the purpose. |

---

## 4. Resource API (`/resources/*`)

### `GET /resources/validate`

| | |
|---|---|
| **Use case** | **High-frequency session heartbeat / liveness check.** Validates that a user's cached session is still active, compares a short-lived "challenge" Bearer JWT against the user's cached authorization JWT, returns minimal identity (`id`, `email`, `jwt`), and publishes a PubSub presence event. Optimized for frequent polling (README: rate-limited — **not yet implemented in code**). |
| **Current** | **Partially protected** — no route middleware. Requires: (1) prior session with `user_id` populated in Redis cache, (2) `Authorization: Bearer <challenge_jwt>` with valid signature and policy match against cached user JWT. |
| **Should be** | **OAuth client** (registered client with valid access token) + rate limiting. Add `CachedJwtLocalIdpAuthMiddleware` or equivalent; verify `sub` matches cached user; implement documented rate limits. |

### `GET /resources/userinfo`

| | |
|---|---|
| **Use case** | **Full user profile for OAuth clients.** Returns `id`, `email`, JWT, and linked ORK profile (persona, park, kingdom, dues, etc.). Primary data endpoint for apps like ORK after OAuth login. |
| **Current** | **OAuth client** — `CachedJwtLocalIdpAuthMiddleware`: requires `Authorization: Bearer` (RS256 JWT), validates via Resource Server on cache miss, caches in Redis. Sets session from token. |
| **Should be** | **OAuth client** with valid access token scoped to the requesting client. Current model is appropriate; add rate limiting per README claim. |

### `GET /resources/jwt`

| | |
|---|---|
| **Use case** | Issue an IDP authorization JWT for the currently logged-in user (browser session). Used by the IDP itself and integrated flows needing a signed policy JWT. |
| **Current** | **Authenticated user (session only)** — `LocalIdpAuthMiddleware`: requires session `user_id`; **rejects** requests that send `Authorization: Bearer` header. Falls back to redirect `/auth/login` if unauthenticated. |
| **Should be** | **Authenticated user (session)** — correct for browser-origin use. Consider CSRF if called from forms; JSON API calls from same-origin JS are fine with session cookie. |

### `GET /resources/profile`

| | |
|---|---|
| **Use case** | **Browser profile management page.** Shows avatar, linked login providers, authorized OAuth apps, ORK profile, admin link. HTML (Twig), not JSON API. |
| **Current** | **Authenticated user (session)** — `LocalIdpAuthMiddleware`. Redirects to login if no session. Session `client_id` must be `amtgard-idp-client-id` if set. |
| **Should be** | **Authenticated user (session)** — correct. |

### `GET /resources/authorizations`

| | |
|---|---|
| **Use case** | JSON list of OAuth clients the user has authorized. |
| **Current** | **OAuth client or IDP session** — `ClientRestrictedAuthMiddleware`: session with `client_id` in allowlist **or** Bearer JWT with `aud` in allowlist + Resource Server validation. |
| **Should be** | **Authenticated user** — user should only see their own authorizations. Current middleware ensures valid client token/session but allowlist is only `amtgard-idp-client-id`. Acceptable if only first-party IDP UI calls this. Third-party clients should not need this endpoint. |

### `POST /resources/profile/link-ork`

| | |
|---|---|
| **Use case** | Link authenticated user's IDP account to an ORK (Amtgard record keeping) account using ORK username/password. |
| **Current** | **OAuth client or IDP session** — `ClientRestrictedAuthMiddleware` (same as above). |
| **Should be** | **Authenticated user (session)** + CSRF token. Handles user credentials (ORK password) — must not be CSRF-able. Currently no CSRF protection. |

### `POST /resources/profile/refresh-ork`

| | |
|---|---|
| **Use case** | Refresh cached ORK profile data from ORK API using stored ORK token. |
| **Current** | **OAuth client or IDP session** — `ClientRestrictedAuthMiddleware`. |
| **Should be** | **Authenticated user (session)** + CSRF. |

### `POST /resources/profile/revoke`

| | |
|---|---|
| **Use case** | Revoke user's authorization for a specific OAuth client (`client_id` in POST body). User-scoped: uses session user ID, not body user ID (good IDOR pattern). |
| **Current** | **OAuth client or IDP session** — `ClientRestrictedAuthMiddleware`. |
| **Should be** | **Authenticated user (session)** + CSRF. Verify user actually has authorization for that `client_id` before revoke. |

---

## 5. Authentication (`/auth/*`)

All auth endpoints are **browser-oriented login/registration flows**. They must be internet-facing for users to log in.

### `GET /auth/login`

| | |
|---|---|
| **Use case** | Display login form; accepts `redirect` and `jwtpublickey` query params for post-login redirect into OAuth flow. |
| **Current** | **Public** |
| **Should be** | **Public** — `redirect` sanitized via `RedirectValidator`. |

### `POST /auth/login`

| | |
|---|---|
| **Use case** | Email/password login; creates session. |
| **Current** | **Public** (no CSRF) |
| **Should be** | **Public** + CSRF token + rate limiting / lockout. |

### `GET /auth/register`

| | |
|---|---|
| **Use case** | Registration form. |
| **Current** | **Public** |
| **Should be** | **Public** |

### `POST /auth/register`

| | |
|---|---|
| **Use case** | Create local account; auto-login via session. |
| **Current** | **Public** (no CSRF) |
| **Should be** | **Public** + CSRF + rate limiting. |

### `GET /auth/logout`

| | |
|---|---|
| **Use case** | Destroy session; redirect home. |
| **Current** | **Public** (anyone can trigger logout for a user via CSRF if session cookie sent) |
| **Should be** | **Authenticated user** via `POST` + CSRF. |

### `GET /auth/google`, `GET /auth/facebook`, `GET /auth/discord`

| | |
|---|---|
| **Use case** | Initiate social OAuth redirect; stores `state` for CSRF protection and optional `redirect` in session. |
| **Current** | **Public** |
| **Should be** | **Public** — correct for OAuth initiation. |

### `GET /auth/google/callback`, `GET /auth/facebook/callback`, `GET /auth/discord/callback`

| | |
|---|---|
| **Use case** | Social provider callback; validates `state`, creates/links user, establishes session, redirects with optional JWT in URL. |
| **Current** | **Public** (provider redirect target); protected by OAuth `state` validation. |
| **Should be** | **Public** (callback URL registered with provider). Remove JWT from redirect URL (security concern). |

---

## 6. OAuth2 server (`/oauth/*`)

Standard OAuth2/OIDC authorization server endpoints for registered clients.

### `GET /oauth/authorize`

| | |
|---|---|
| **Use case** | **OAuth2 authorization endpoint.** Third-party apps redirect users here to begin authorization code + PKCE flow. Validates client, redirect URI, scopes. Requires user login (session) and consent (unless previously authorized). |
| **Current** | **Public entry** — no middleware. League OAuth2 Server validates request params. User session required to complete. Redirects unauthenticated users to `/auth/login`. |
| **Should be** | **Public entry** — correct per OAuth2 spec. Client validation via registered `clients` table. |

### `POST /oauth/authorize`

| | |
|---|---|
| **Use case** | Stub (returns empty response). |
| **Current** | **Public** — no-op. |
| **Should be** | Remove or implement if needed. |

### `POST /oauth/token`

| | |
|---|---|
| **Use case** | **OAuth2 token endpoint.** Exchange authorization code (+ PKCE) or refresh token for access/refresh tokens. Confidential clients authenticate with `client_id` + `client_secret`. |
| **Current** | **Public** — authenticated via OAuth2 client credentials/code per League OAuth2 Server. |
| **Should be** | **Public** per OAuth2 spec. Rate limit; generic error responses (no internal exception leakage). |

### `GET /oauth/approve`, `POST /oauth/approve`

| | |
|---|---|
| **Use case** | **User consent screen.** Shows requesting client name and scopes; user Allow/Deny. POST sets `$_SESSION['approved']` and records client authorization in DB. |
| **Current** | **Session implied** — no explicit middleware, but only reachable during active OAuth flow with session. No CSRF on POST. |
| **Should be** | **Authenticated user (session)** + CSRF on POST. Critical — CSRF could force OAuth approval. |

---

## 7. Management (`/management/*`)

### `GET /management/cleantokens`

| | |
|---|---|
| **Use case** | **Operational maintenance.** Deletes expired access tokens, refresh tokens, and auth codes. Intended for cron/ops automation. |
| **Current** | **Management key** — `ManagementMiddleware`: `?key=` must match `MANAGEMENT_KEY` (≥32 chars). Key in query string (logged in access logs). |
| **Should be** | **Service / internal** — key via `Authorization` header; not internet-routable if possible. Cron on private network or k8s internal job. |

### `GET /management/clients`

| | |
|---|---|
| **Use case** | **Admin UI** — list all OAuth clients including secrets. |
| **Current** | **Admin** — `LocalIdpAuthMiddleware` (session) + `LocalAdminUserMiddleware` (IAM policy `IDP/EditClient`). |
| **Should be** | **Admin** — correct. Stop displaying client secrets in HTML; show once at creation. |

### `POST /management/clients`

| | |
|---|---|
| **Use case** | **Admin** — register new OAuth client. |
| **Current** | **Admin** — session + IAM admin policy. No CSRF. |
| **Should be** | **Admin** + CSRF. Validate `redirect_uri` on create. |

### `POST /management/clients/{id}`

| | |
|---|---|
| **Use case** | **Admin** — update existing OAuth client. |
| **Current** | **Admin** — session + IAM admin policy. |
| **Should be** | **Admin** + CSRF. |

---

## Summary matrix

| Endpoint | Method | Use case | Current access | Should be |
|----------|--------|----------|----------------|-----------|
| `/` | GET | Home page | Public | Public |
| `/swagger` | GET | API docs UI | Public | Public (dev) / Restricted (prod) |
| `/openapi.json` | GET | OpenAPI spec | Public | Public (dev) / Restricted (prod) |
| `/docs/*` | GET | Docsify docs | Public | Public (dev) / Restricted (prod) |
| `/api/is_authorized` | POST | Policy evaluation service | Public | Service/internal + rate limit |
| `/resources/validate` | GET | Session heartbeat / presence | Session + challenge JWT (no middleware) | OAuth client + rate limit |
| `/resources/userinfo` | GET | Full user profile (JSON) | Bearer JWT + cache | OAuth client + rate limit |
| `/resources/jwt` | GET | Issue IDP JWT for session user | Session only | Authenticated user (session) |
| `/resources/profile` | GET | Profile page (HTML) | Session | Authenticated user (session) |
| `/resources/authorizations` | GET | List authorized apps | Client allowlist + Bearer/session | Authenticated user (first-party) |
| `/resources/profile/link-ork` | POST | Link ORK account | Client allowlist + Bearer/session | Authenticated user + CSRF |
| `/resources/profile/refresh-ork` | POST | Refresh ORK profile | Client allowlist + Bearer/session | Authenticated user + CSRF |
| `/resources/profile/revoke` | POST | Revoke app authorization | Client allowlist + Bearer/session | Authenticated user + CSRF |
| `/auth/login` | GET/POST | Login | Public | Public + CSRF (POST) |
| `/auth/register` | GET/POST | Register | Public | Public + CSRF (POST) |
| `/auth/logout` | GET | Logout | Public | Authenticated + POST + CSRF |
| `/auth/{provider}` | GET | Social OAuth start | Public | Public |
| `/auth/{provider}/callback` | GET | Social OAuth callback | Public + state | Public + state |
| `/oauth/authorize` | GET | OAuth authorization | Public + OAuth validation | Public (OAuth spec) |
| `/oauth/authorize` | POST | Stub | Public | Remove/implement |
| `/oauth/token` | POST | Token exchange | OAuth client auth | Public (OAuth spec) |
| `/oauth/approve` | GET/POST | User consent | Session (implicit) | Authenticated + CSRF (POST) |
| `/management/cleantokens` | GET | Token cleanup job | Management key | Internal service |
| `/management/clients` | GET | List OAuth clients | Admin (IAM) | Admin |
| `/management/clients` | POST | Create OAuth client | Admin (IAM) | Admin + CSRF |
| `/management/clients/{id}` | POST | Update OAuth client | Admin (IAM) | Admin + CSRF |

---

## Known gaps (current vs. should be)

1. **CSRF** — `CsrfTokenManager` exists but is not wired to browser POST forms (`/auth/*`, `/oauth/approve`, profile actions, management).
2. **Rate limiting** — README claims limits on `userinfo`/`validate`; not implemented.
3. **`/resources/validate`** — weakest resource endpoint; trusts session + cache without route middleware.
4. **`/api/is_authorized`** — intentionally public for service use; needs operational hardening not user auth.
5. **JWT in login redirect URL** — `BaseAuthController` appends `?jwt=` to redirect (token leakage risk).
6. **Documentation endpoints** — fully public in production exposes API surface.
7. **Management key in query string** — should move to header.
8. **AuthorizedClients allowlist** — hardcoded to `amtgard-idp-client-id` only; third-party OAuth client tokens cannot call `/resources/userinfo` unless cache path used differently.

---

## OAuth client onboarding flow (context)

Third-party apps are registered in the `clients` database table (via admin UI or manual). They use:

1. `GET /oauth/authorize` — user redirected from app
2. User logs in via `/auth/*` if needed
3. `GET/POST /oauth/approve` — consent if first time
4. `POST /oauth/token` — app exchanges code for tokens
5. `GET /resources/userinfo` — app fetches profile with access token

Public clients use PKCE; confidential clients use `client_secret` at the token endpoint.
