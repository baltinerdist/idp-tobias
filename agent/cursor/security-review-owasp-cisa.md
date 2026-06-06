# Security Review Plan — OWASP Top 10:2025 & CISA AA23-208A

**Branch context:** `security/refactor-and-review` (stacked on test-coverage work)  
**Date:** 2026-06-05  
**Status:** Recommendations for consideration — not all items are agreed fixes.

References:
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [CISA AA23-208A — Preventing Web Application Access Control Abuse (IDOR)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-208a)

---

## How to use this document

Each item is tagged:

| Tag | Meaning |
|-----|---------|
| **AGREE** | Likely worth implementing |
| **CONSIDER** | Valid tradeoff; needs design decision |
| **DISPUTE** | Automated review flagged this; may be intentional or wrong framing |
| **DONE** | Already addressed (partially or fully) |

---

## Executive summary

Solid foundations exist: parameterized SQL, `password_hash`/`password_verify`, OAuth social `state` checks, League OAuth2 Server, and `RedirectValidator` for several redirect paths.

Highest-value follow-ups cluster around session/CSRF hardening, unsafe deserialization, JWT-in-URL, misconfiguration in production, and closing gaps on endpoints that trust session alone. Some automated findings overstate risk or misunderstand intent (notably `/api/is_authorized`).

---

## Disputed / intentional design (read first)

### `POST /api/is_authorized` — must stay public — **DISPUTE**

**Automated finding:** Unauthenticated policy oracle; remove or require auth.

**Actual intent:** This endpoint *is* the authorization check. Other services call it to evaluate IAM policy/requirements. Requiring user/session auth would defeat its purpose.

**Still worth considering (without making it private):**
- Rate limiting per source IP / API key (if callers can present one)
- Input size/depth limits on `policy` JSON
- Network restriction (internal VPC, allowlisted service mesh) if not meant for the public internet
- Document what information probing reveals and whether that's acceptable
- Structured audit logging of calls (not full policy bodies if sensitive)

**Do not:** Gate behind end-user login or remove without a replacement contract for callers.

---

## OWASP Top 10:2025 — findings & recommendations

### A01:2025 — Broken Access Control

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| `POST /api/is_authorized` public | **DISPUTE** | — | See above. Harden operationally, don't authenticate like a user endpoint. |
| `GET /resources/validate` no route middleware | **AGREE** | Critical | Trusts `$_SESSION['user_id']` + Redis + Bearer challenge JWT. Add proper middleware, verify `sub` matches session, add rate limits. |
| Redis cache fast-path skips revocation check | **CONSIDER** | High | `CachedJwtLocalIdpAuthMiddleware` bypasses `ResourceServer` on cache hit. Tradeoff for latency vs. revocation freshness — decide TTL/invalidation policy. |
| `revokeAuthorization` doesn't revoke tokens | **AGREE** | Medium | DB authorization removed but access tokens may remain valid until expiry. Users may expect full revoke. |
| OAuth approve CSRF (`POST /oauth/approve`) | **AGREE** | High | `action=allow` sets `$_SESSION['approved']` with no CSRF token. Serious during active OAuth flow. |
| `revokeAuthorization` scopes by session user | **DONE** | — | Uses `$user->getUserId()` from session, not body — good IDOR pattern per CISA. |

**CISA AA23-208A:** Default-deny and per-request authorization apply to user-data endpoints. `/api/is_authorized` is a policy engine, not a user-object accessor — frame IDOR mitigations separately.

---

### A02:2025 — Security Misconfiguration

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| `display_errors` always on in `public/index.php` | **AGREE** | High | Gate on `APP_DEBUG`; never in production. |
| Wildcard CORS (`*` in app + nginx) | **CONSIDER** | Medium | May be intentional for public API docs / cross-origin clients. Restrict on cookie-session routes if possible. |
| Session cookie params not set (`Secure`, `HttpOnly`, `SameSite`) | **AGREE** | High | Set explicitly in `SessionMiddleware`; don't rely on PHP defaults. |
| `APP_SECRET` in `.env.example` but unused | **CONSIDER** | Low | Wire up for CSRF/session signing or remove from docs. |
| `Logger::DEBUG` always in `config/container.php` | **AGREE** | Medium | Environment-based log level; redact PII in auth flows. |
| Weak `.env.example` placeholders | **CONSIDER** | Low | Documentation hygiene. |
| Public `/swagger`, `/openapi.json`, `/docs/*` | **CONSIDER** | Low | Fine for dev; restrict in production if desired. |

---

### A03:2025 — Software Supply Chain Failures

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| No `composer audit` in CI | **AGREE** | Medium | Add to pipeline; pin/review dependency updates. |
| Dev tooling in `Dockerfile.dev` (Xdebug, etc.) | **CONSIDER** | Low | Ensure production images are separate; dev stack not internet-facing. |

---

### A04:2025 — Cryptographic Failures

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| JWT in redirect URL after login (`BaseAuthController`) | **AGREE** | Critical | `Location: {redirect}?jwt=...` leaks to history, Referer, logs. Prefer one-time code, POST+fragment, or HttpOnly cookie. |
| Client secrets shown in management HTML | **AGREE** | High | Show once at creation; hash at rest; mask in list UI. |
| Client secret compared with `==` | **CONSIDER** | Low | `hash_equals` is better hygiene; network-bound OAuth makes timing leak lower priority. |
| Management key in query string (`?key=`) | **AGREE** | Medium | Move to header; use `hash_equals`; avoid logging. |

---

### A05:2025 — Injection

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| SQL injection | **DONE** | — | Parameterized queries in repositories — maintain. |
| `json_decode` on untrusted `policy` in `/api/is_authorized` | **CONSIDER** | Medium | Schema/depth/size limits if endpoint is public-facing. |
| No `eval` / shell execution in app code | **DONE** | — | Keep in review checklist. |

---

### A06:2025 — Insecure Design

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| `JwtChallenge::validateChallenge()` always `true` | **AGREE** | High | Stub defeats one-time challenge design; implement Redis-backed validate+consume. |
| No rate limiting (README claims it for userinfo/validate) | **AGREE** | High | Implement or fix README. Apply to `/auth/*`, `/oauth/token`, `/resources/validate`. |
| CSRF not deployed (`CsrfTokenManager` exists, unused) | **AGREE** | High | Forms: login, register, oauth approve, profile POSTs, management. |
| `validateGrant()` always `true` | **CONSIDER** | Medium | Per-client grant restrictions may be overkill if all clients are equally trusted. |
| Account enumeration on register | **CONSIDER** | Low | Generic error messages vs. UX clarity. |

---

### A07:2025 — Authentication Failures

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| No `session_regenerate_id()` on login | **AGREE** | High | Call in `finalizeAuthorization` after successful auth. |
| Bearer token promotes to session (`LocalIdpAuthMiddleware`) | **CONSIDER** | Medium | Convenience for browser API use; may be intentional. Regenerate ID if kept. |
| No login lockout / MFA | **CONSIDER** | Medium | Progressive delay or CAPTCHA — balance vs. support burden. |
| `GET /auth/logout` | **CONSIDER** | Low | Logout CSRF is nuisance-level; POST+CSRF is cleaner. |
| Social OAuth `state` validation | **DONE** | — | `OAuth2StateManager` / `OAuthCallbackValidator` in place. |

---

### A08:2025 — Software or Data Integrity Failures

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| `unserialize($_SESSION['authRequest'])` in OAuth flow | **AGREE** | Critical | Prefer JSON DTO or `allowed_classes` whitelist; session compromise + gadget chains are the risk. |
| `unserialize()` on Redis cache values | **AGREE** | Critical | Replace with JSON + factory; lock down Redis (TLS, ACL, private network). |
| CSRF on state-changing browser requests | **AGREE** | High | See A06. |

---

### A09:2025 — Security Logging and Alerting Failures

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| No structured security event logging | **CONSIDER** | Medium | Failed logins, OAuth state failures, admin actions — useful but needs log pipeline. |
| PII in DEBUG logs (social auth) | **AGREE** | Medium | Redact or raise log level in production. |
| No audit trail for OAuth client management | **AGREE** | Medium | Who created/updated which client. |

---

### A10:2025 — Mishandling of Exceptional Conditions

| Item | Tag | Severity | Notes / recommendation |
|------|-----|----------|------------------------|
| Token endpoint returns `$exception->getMessage()` on 500 | **AGREE** | High | Generic client error; log server-side. |
| Social login shows `$e->getMessage()` in alert | **CONSIDER** | Medium | Generic user message may be enough; log details server-side. |
| `display_errors` in production | **AGREE** | High | See A02. |

---

## CISA AA23-208A — IDOR & access control

CISA focus: don't let callers access/modify other users' objects by swapping identifiers.

| CISA guidance | Applicability here | Tag |
|---------------|-------------------|-----|
| Server-side authZ on every sensitive request | Gaps on `/resources/validate`; `/api/is_authorized` is different (policy eval, not object access) | **AGREE** / **DISPUTE** |
| Don't trust client-supplied IDs alone | `revokeAuthorization` correctly uses session user ID | **DONE** |
| Centralize authorization | `UserAuthority`, IAM policies, middleware — extend consistently | **CONSIDER** |
| Non-guessable IDs (UUIDs) | Integer IDs OK if authZ is solid | **CONSIDER** |
| Pen testing / negative authZ tests | Add tests: user A cannot affect user B's resources | **AGREE** |

---

## Prioritized roadmap (for consideration)

### P0 — Strong consensus

1. Fix `display_errors` / production error handling
2. Replace `serialize`/`unserialize` in session and Redis
3. Stop putting JWTs in redirect URLs (design alternative)
4. Harden `/resources/validate` (middleware, `sub` check, rate limits)
5. Deploy CSRF on browser POST flows (especially `/oauth/approve`)

### P1 — High value, some design needed

6. `session_regenerate_id(true)` on login/OAuth complete
7. Session cookie flags (`Secure`, `HttpOnly`, `SameSite`)
8. Implement `JwtChallenge` validation properly
9. Rate limiting on auth/token/validate endpoints
10. Generic errors on OAuth token endpoint failures

### P2 — Hardening

11. Revoke access tokens when user revokes client authorization
12. Hash OAuth client secrets at rest; don't display in admin list
13. Management key via header + `hash_equals`
14. Environment-based log levels; redact PII
15. `composer audit` in CI

### P3 — Optional / tradeoff-heavy

16. Login lockout / CAPTCHA
17. `POST` logout with CSRF
18. Per-client grant type restrictions
19. Generic registration errors (anti-enumeration)
20. Restrict CORS and public docs in production
21. Operational hardening of `/api/is_authorized` (rate limit, network ACL, input limits) — **not** user authentication

---

## Already in good shape

- Parameterized SQL
- `password_hash` / `password_verify`
- OAuth social callback state validation
- `RedirectValidator` on several redirect paths
- Scope allowlist (`ScopeRepository`)
- Management key minimum length
- Admin routes: `LocalIdpAuthMiddleware` + `LocalAdminUserMiddleware`
- No `eval` / `shell_exec` in application code
- Security utilities started: `src/Utility/Security/` (`OAuth2StateManager`, `RedirectValidator`, `ScriptAlertResponse`, `CsrfTokenManager`, `OAuthCallbackValidator`)

---

## Key files (quick index)

| Area | Paths |
|------|-------|
| Routes | `config/routes.php` |
| Middleware | `config/middleware.php`, `src/Middleware/*.php` |
| OAuth server | `src/Controllers/Server/OAuth2ServerController.php` |
| Auth / sessions | `src/Controllers/Client/*`, `src/Middleware/SessionMiddleware.php` |
| Policy API | `src/Controllers/Api/ApiController.php` |
| Validate endpoint | `src/Controllers/Resource/LowLatencyController.php` |
| JWT | `src/Utility/Jwt.php`, `src/Models/AmtgardIdpJwt.php` |
| Redis cache | `src/Persistence/Server/Repositories/RedisCacheRepository.php` |
| Admin | `src/Controllers/Management/ManagementController.php` |
| Templates | `templates/login_form.twig`, `oauth_approve.twig`, `management/clients.twig`, `profile.twig` |
| Deploy | `public/index.php`, `nginx.idp.config`, `Dockerfile.dev`, `.env.example` |
| Security utilities | `src/Utility/Security/` |

---

## Notes / decisions log

| Date | Decision |
|------|----------|
| 2026-06-05 | `/api/is_authorized` remains public by design — operational hardening only, not user auth. |
| | Full plan recorded for review; items tagged AGREE/CONSIDER/DISPUTE for triage. |
