# Auth Contract

The wire contract between **Auth Service** (the IdP) and a **consumer application**.
This is the source of truth for what the HTTP endpoints accept and return, what the
tokens contain, and what a consumer must do to integrate securely. Consumers should
not hand-roll against these endpoints directly — use the shared SDKs
([`auth-client`](../auth-client) for backends, [`auth-client-web`](https://github.com/HyxiaoGe/auth-client-web)
for browsers), which implement this contract. This document explains what those SDKs
do under the hood and what guarantees the IdP provides.

Base URL below is written as `${AUTH_URL}` (dev default `http://localhost:8100`).
Replace it with your deployment's base URL.

## Roles

- **Auth Service (IdP)** — owns user identity, social login (Google/GitHub), the
  shared browser session, and JWT issuance. Signs tokens with RS256.
- **Consumer app** — a registered application (has a `client_id` + a `redirect_uri`
  allowlist). Drives the browser through the SSO flow, then verifies the resulting
  JWTs against the IdP's JWKS. Never sees a user password.
- **`auth-client-web`** — browser SDK that runs the SSO flow (PKCE login redirect,
  state-validated callback, token refresh/revoke).
- **`auth-client`** — Python SDK that verifies access tokens against JWKS.

## SSO flow (single sign-on)

The win: a user who already has a live IdP session lands in a consumer app already
logged in, with no second login screen.

```
App load
  └─ auth-client-web.silentLogin()         top-level redirect →
       GET ${AUTH_URL}/auth/authorize?...&prompt=none
         ├─ live IdP session  → 302 back to redirect_uri?code=...&state=...
         └─ no IdP session    → 302 back to redirect_uri?error=login_required&state=...
                                  (SDK treats this as "not logged in", shows login)

Interactive login
  └─ auth-client-web.login('google')        top-level redirect →
       GET ${AUTH_URL}/auth/authorize?...&provider=google
         → IdP runs Google/GitHub OAuth, starts an IdP session (Set-Cookie),
           302 back to redirect_uri?code=...&state=...

Callback page (redirect_uri)
  └─ auth-client-web.handleCallback()
       1. validate returned state == stored state (CSRF)
       2. POST ${AUTH_URL}/auth/oauth/token { code, client_id, code_verifier }
            → { access_token, refresh_token, token_type:"bearer", expires_in:900 }
       3. GET ${AUTH_URL}/auth/userinfo  (Bearer access_token)

API calls
  └─ Authorization: Bearer <access_token>   (refresh on demand before expiry / on 401)

Backend
  └─ auth-client.JWTValidator.verify(token)  → AuthenticatedUser
```

`silentLogin()`/`login()` use a **top-level browser navigation** (not an iframe) so the
IdP session cookie (`SameSite=Lax`) is sent. The cost is one full-page redirect flash.

## Endpoints (consumer-facing)

All paths are relative to `${AUTH_URL}`.

### `GET /auth/authorize` — SSO front door

OAuth 2.0 authorization endpoint, PKCE **mandatory**, `response_type=code` only.

| Param | Req | Notes |
|-------|-----|-------|
| `client_id` | yes | Your registered client id. |
| `redirect_uri` | yes | Must **exactly** match a registered redirect uri of the active app. |
| `response_type` | yes | Only `code` is accepted. |
| `code_challenge` | yes | Base64url(SHA-256(verifier)). |
| `code_challenge_method` | yes | Must be `S256` (plain is rejected). |
| `state` | rec | Opaque value echoed back unchanged; the consumer's CSRF defense. |
| `prompt` | opt | `none` (silent probe), `login`, `select_account`. |
| `provider` | opt | `google` or `github` (used when there is no live session). |
| `nonce`, `scope` | opt | Accepted; see [Notes](#notes--current-limits). |

Outcomes:
- Live session, `prompt` not `login`/`select_account` → the IdP first confirms the user is
  active and the session's `auth_generation` still matches PostgreSQL, then returns
  `302 redirect_uri?code=<code>&state=<state>`. A stale session is deleted and handled as
  no session instead of repeatedly minting codes that cannot be redeemed.
- `prompt=none`, no session → `302 redirect_uri?error=login_required&error_description=no+active+session&state=<state>`.
- No session, `provider=google|github` → `302` to social consent; unsupported providers such as `email` → `302 redirect_uri?error=invalid_request&...&state=`.
- Bad `client_id`/unregistered `redirect_uri` → **`400` JSON** `{error:"invalid_client", error_description}` (never redirects to an unvalidated uri).
- Bad `response_type` → `400` JSON `{error:"unsupported_response_type"}`.
- Missing/`!=S256` PKCE → `302 redirect_uri?error=invalid_request&...&state=`.

Errors use `400` JSON **before** `redirect_uri` is validated, and a `302` redirect with
`?error=&error_description=&state=` **after** it is known-good.

### Headless email OTP — in-app interaction

Web consumers keep the two-step email interaction inside their own login dialog. This
transport uses the same authorization-code + PKCE flow and does not issue access or
refresh tokens directly. Auth Service no longer provides a hosted email login page.

Check
`GET /auth/capabilities?client_id=<client>&redirect_uri=<percent-encoded exact callback>`
first. The additive `email_headless_login` field is `true` only when both query parameters
are present, the database still contains that active app and exact redirect URI, email
delivery is ready, the independent headless switch is enabled, and the request `Origin`
passes every rule below. The legacy `email_login` field remains in the response for
schema compatibility but is always `false`; calls without both query parameters return
`email_headless_login: false`.

The Origin must be an allowlisted HTTPS or loopback HTTP web origin, exactly equal the
registered redirect URI's origin, and be **schemeful same-site** with `AUTH_BASE_URL`.
Sibling subdomains such as `authmail.seanfield.org` and `dev.seanfield.org` are allowed;
`auth.example.com` and `app.other.com`, different schemes, different IPs, `app://-`, and
`Origin: null` are rejected. Registrable sites use an offline Public Suffix List including
private suffixes, so `co.uk` and multi-tenant domains such as `github.io` are not merged
naively. Packaged Electron origins are not eligible for this web-only protocol.

All three headless requests use JSON, send `credentials: "include"`, and require an exact
`Origin`. That origin must both appear in `CORS_ORIGINS` and equal the origin of the exact
registered `redirect_uri`. CORS is not treated as authentication: send and verify also
require the HttpOnly browser-binding cookie plus the returned CSRF token in the
`X-CSRF-Token` header. Responses are `Cache-Control: no-store` and vary by Origin.

#### `POST /auth/email/headless/start`

Request:

```json
{
  "client_id": "fusion",
  "redirect_uri": "https://fusion.example/auth/callback",
  "response_type": "code",
  "state": "<32+ character base64url app state>",
  "code_challenge": "<43 character base64url S256 challenge>",
  "code_challenge_method": "S256"
}
```

The IdP validates the Origin policy, readiness, active app, and exact redirect URI before
creating any state. PKCE must be the exact 43-character base64url SHA-256 challenge and
`state` must contain at least 32 base64url characters. Success returns `201`, creates the existing
HttpOnly/Secure/host-only `SameSite=Lax` browser-binding cookie, and stores all OAuth
context server-side:

```json
{ "flow_id": "...", "csrf_token": "...", "expires_in": 600, "code_length": 6 }
```

#### `POST /auth/email/headless/send`

Header `X-CSRF-Token: <start.csrf_token>`, request:

```json
{ "flow_id": "...", "email": "person@example.com" }
```

Existing, inactive and unknown accounts receive the same `202` response shape. The
destination is derived only from the submitted value, never from account lookup:

```json
{
  "accepted": true,
  "next": "verify",
  "expires_in": 300,
  "resend_after": 60,
  "masked_destination": "p***@example.com"
}
```

Delivery runs after the response. A `202` means the request was accepted, not that an
account exists or SMTP delivery succeeded.

#### `POST /auth/email/headless/verify`

Header `X-CSRF-Token: <start.csrf_token>`, request:

```json
{ "flow_id": "...", "code": "123456" }
```

Before consuming the OTP, the IdP revalidates the active app and exact redirect URI.
Success consumes the OTP once, starts a fresh IdP session with `amr=email_otp`, and returns
only a PKCE-bound one-time authorization code plus the original state:

```json
{ "code": "...", "state": "<original app state>", "expires_in": 300 }
```

The consumer MUST compare `state` with its locally stored value, then exchange `code`
through `POST /auth/oauth/token` using the original `client_id` and `code_verifier`.

Stable headless error codes include:

| HTTP | `error` | Meaning |
|------|---------|---------|
| 400 | `invalid_client` / `invalid_request` | OAuth request or app configuration is invalid. |
| 400 | `invalid_code` | Verification code is invalid, expired, or exhausted. |
| 403 | `origin_not_allowed` / `invalid_interaction` | Origin or flow Cookie/CSRF binding failed. |
| 410 | `interaction_expired` | A trusted recovery record exists; restart the interaction. |
| 429 | `rate_limited` | Retry after `retry_after` / `Retry-After`. |
| 503 | `delivery_unavailable` | Headless email login or delivery is unavailable. |

### `POST /auth/oauth/token` — code → tokens

Request (JSON):
```json
{ "code": "<one-time auth code>", "client_id": "<client_id>", "code_verifier": "<pkce verifier>" }
```
- The `code` is single-use. `client_id` must match the app the code was minted for.
- `code_verifier` is required for codes minted via `/auth/authorize` (PKCE-bound).
- The code is also bound to the user's current `auth_generation`. A code minted before
  `/auth/logout` cannot be exchanged after logout, regardless of whether it came from
  email OTP, Google, GitHub, or silent SSO. Legacy codes without this binding fail closed.
- No `client_secret` — consumers are public PKCE clients.

Response `200`:
```json
{ "access_token": "<jwt>", "refresh_token": "<jwt>", "token_type": "bearer", "expires_in": 900 }
```
`expires_in` is the **access** token lifetime in seconds. Errors → `400` with a message.

### `POST /auth/token/refresh` — rotate tokens

Request `{ "refresh_token": "<jwt>" }` → Response `200` same shape as above, with a **new
pair**. Refresh tokens **rotate**: the old one is revoked on each refresh. Presenting an
**already-revoked** refresh token normally becomes a reuse/theft event: the IdP revokes
that app's refresh-token lineage and returns `401` (a legacy token without an app binding
falls back to account-wide revocation). A narrowly timed, first replay of a token revoked
by normal rotation may receive one grace re-issue so a lost HTTP response does not create
a false theft event; the grace is single-use and is disabled after logout. A token that is
unknown (not in the store), fails signature/type validation, or carries an auth generation
different from the locked user/DB token row simply returns `401`. Consumers must still
persist only the newest refresh token and coalesce concurrent refreshes.

Refresh and logout serialize on the PostgreSQL user row. Refresh locks the user first and
then the refresh-token row; logout takes the same user lock, increments `auth_generation`,
and revokes every refresh token in one transaction. Therefore a refresh that commits first
is subsequently swept by logout, while a refresh that runs second sees the new generation
and cannot mint a successor.

### `POST /auth/token/revoke` — drop a refresh token

Request `{ "refresh_token": "<jwt>" }` → `200 {message}`. Idempotent. Does **not**
invalidate already-issued access tokens (they remain valid until `exp`) and does not end
the IdP session. `auth-client-web.logout()` calls this best-effort.

### `GET /auth/userinfo` — current user (Bearer)

Requires `Authorization: Bearer <access_token>`. Response `200`:
```json
{ "id": "<uuid>", "email": "...", "name": "... | null", "avatar_url": "... | null",
  "is_superuser": false, "is_active": true, "created_at": "...",
  "preferences": { "locale": "...", "timezone": "...", "theme": "..." } }
```
Missing/invalid token → `401`. The fields beyond `id`/`email` are convenience profile
data; treat `name`/`avatar_url` as nullable.

### `POST /auth/logout` — single logout (end IdP session)

`POST` only (so it cannot be triggered by cross-site GET navigation). `post_logout_redirect_uri`
and `client_id` may be sent **either** as a JSON body `{ "post_logout_redirect_uri": "...",
"client_id": "..." }` **or** as urlencoded form fields — the form variant lets a top-level
`<form method=POST>` carry the `SameSite=Lax` session cookie to this cross-site, POST-only
endpoint (this is the browser SDK's single-logout path). Ends the shared IdP session,
atomically increments the user's `auth_generation`, revokes all of the user's refresh
tokens, and clears the session cookie. If
`post_logout_redirect_uri` is a registered redirect uri → `302` there (open-redirect
guarded); otherwise `200 {message}`. When `client_id` is supplied the uri must be
registered **for that app** (tighter); without it, any active app's registered uri matches.
For true cross-app logout, the IdP also writes a **per-user access-token revocation marker**
(see "Single-Logout revocation" below) so other apps' already-issued access tokens stop
working on their next request instead of lingering until `exp`. This is the cross-app
logout; per-app token revoke is `/auth/token/revoke`.

### `GET /.well-known/jwks.json` — verification keys

The only discovery endpoint (there is no `/.well-known/openid-configuration`). Public.
```json
{ "keys": [ { "kty":"RSA", "use":"sig", "alg":"RS256", "kid":"auth-key-1", "n":"<b64url>", "e":"<b64url>" } ] }
```
Consumers fetch this (cached), match the token header `kid`, and verify the RS256
signature. No secret is shared with consumers.

## Tokens

Both tokens are RS256 JWTs. Header: `{ "alg":"RS256", "kid":"auth-key-1", "typ":"JWT" }`.

**Access token** (15 min):

| Claim | Value |
|-------|-------|
| `sub` | user id (UUID string) |
| `email` | user email |
| `iss` | `${AUTH_URL}` (the IdP base url, verbatim) |
| `iat` / `exp` | issued-at / +15 min |
| `jti` | unique id |
| `type` | `"access"` |
| `auth_generation` | user's authentication generation when the token was issued |
| `aud` | the app's `client_id` (present when issued with one) |
| `scopes` | `["admin"]` for superusers else `["user"]` (present when non-empty) |

**Refresh token** (30 days): `sub`, `iss`, `iat`, `exp` (+30d), `jti`, `type:"refresh"`,
`auth_generation`, `aud`. No `email`/`scopes`. Stored server-side (hashed, with the same
generation) for rotation + reuse detection. The first deployment introducing this field
raises every existing user to generation 1 while legacy refresh rows and JWTs remain at
generation 0, intentionally forcing a one-time re-login across existing applications.
New users start at generation 0 and only advance on account-wide logout.

## Verifying tokens (backend requirements)

Use [`auth-client`](../auth-client). Configure the validator to enforce the full
contract — not just the signature:

```python
from auth import JWTValidator

validator = JWTValidator(
    jwks_url=f"{AUTH_URL}/.well-known/jwks.json",
    issuer=AUTH_URL,            # reject tokens from a different issuer
    audience=CLIENT_ID,         # reject tokens minted for a different app
    require_token_type="access" # reject refresh tokens on protected routes
)
user = validator.verify(token)  # -> AuthenticatedUser(sub, email, aud, scopes, raw_payload)
```

Why each option matters:
- **`issuer`** — the IdP enforces `iss`, but your validator should pin it too.
- **`audience`** — the IdP does **not** enforce `aud` (it varies per app), so a token
  minted for app A is signature-valid for app B. Setting `audience` to your own
  `client_id` is how you scope tokens to your app.
- **`require_token_type="access"`** — a refresh token is signature-valid; this rejects it
  on access-protected routes.

Signature alg is pinned to `RS256`. JWKS is cached (`cache_ttl`, default 300s).

### Single-Logout revocation (in-flight access tokens)

Access tokens are stateless JWTs, so the signature check above passes even after the user
logged out elsewhere — the token stays valid until `exp` (≤15 min). To honor "logout once =
logout everywhere", `POST /auth/logout` writes a **per-user revocation marker** into the
**shared Redis** that every consumer on this deployment already connects to:

| | |
|-|-|
| key | `revoked_user:{sub}` (`sub` = the access token's user id) |
| value | wall-clock epoch seconds of the logout instant, as a **float** (`time.time()`) |
| ttl | access-token lifetime — once it elapses no pre-logout token can still be unexpired, so it self-cleans |
| rule | after signature/issuer/audience/type validation, reject (`401`) iff the marker exists **and** `token.iat < marker` |

**Keep the marker a float, and use strict `<`.** A JWT `iat` is *integer* epoch seconds
(sub-second precision is truncated when the token is minted), while the marker is the
fractional logout instant. The comparison therefore **over-revokes by design**: every token
minted before the logout instant is rejected (the guarantee we want), and the only token that
would be falsely revoked is a re-login completing inside the *same wall-clock second* as the
logout — which cannot happen, because an OAuth re-auth takes several round-trips, so a fresh
token's `iat` always lands in a later second and survives. Do **not** "simplify" by storing
`int(logout_time)`: a token minted 0.3 s *before* a logout at `T.5` would then truncate to
`iat == T`, pass `T < T`, and wrongly stay valid for up to its full TTL — a real hole.

A consumer backend should perform this check right after `validator.verify(token)` and
before trusting the token. It is one Redis `GET` per authenticated request (cheap on the
shared single-box Redis). **Fail open:** because the check is now on the auth hot path of
every request, a Redis read error must be swallowed (log + treat as not-revoked), not turned
into a `500` — otherwise a single shared-Redis blip locks every user out of every app. The
revocation lag then degrades to the token's own `exp` (≤15 min) until Redis recovers.
Likewise, `/auth/logout` writes the marker best-effort: a write failure is logged but does
not fail the logout (the cookie + session are still cleared and refresh tokens still revoked).

This marker is the only thing that makes a foreign logout take effect on the **next API call**
rather than after the access-token TTL. Without shared-Redis access a consumer degrades to
"valid until `exp`"; instant cross-app logout then requires introspection or back-channel
logout (not currently provided).

## Security requirements for consumers

- **PKCE S256** on every `/auth/authorize` (the SDK does this; `plain` is rejected).
- **Validate `state`** on the callback before exchanging the code — this is the app's
  primary CSRF defense; `SameSite` is only defense-in-depth.
- **Verify `issuer`, `audience` (= your `client_id`), and token `type`** on the backend
  (see above).
- Use **HTTPS** in production (the IdP session cookie is `Secure` + `__Host-` only over
  HTTPS) and an **HTTPS** `redirect_uri`.
- `redirect_uri` is matched by **exact string membership** against your registered list —
  no wildcards or prefix matching. Register every concrete callback url you use.

## Notes & current limits

- One signing key (`kid:"auth-key-1"`). Verify by matching `kid` against JWKS; do not
  hardcode the key.
- `nonce` is accepted at `/auth/authorize` but no `id_token` is issued and `nonce` is not
  embedded in the access token. There is no OIDC `id_token` today — identity comes from
  the access token claims + `/auth/userinfo`.
- `scope` is accepted at `/auth/authorize` but token scopes are derived from the user
  (superuser → `["admin"]`, else `["user"]`), not from the requested scope.
- Provider set is global (`google`, `github`) — not configured per client.

See [ONBOARDING.md](./ONBOARDING.md) to register a new app and wire it up, and
[`examples/`](../examples) for copy-paste backend and frontend integrations.
