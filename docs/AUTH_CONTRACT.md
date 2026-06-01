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
- Live session, `prompt` not `login`/`select_account` → `302 redirect_uri?code=<code>&state=<state>`.
- `prompt=none`, no session → `302 redirect_uri?error=login_required&error_description=no+active+session&state=<state>`.
- No session, valid `provider` → `302` to Google/GitHub consent (IdP completes it, then redirects back with `code`).
- Bad `client_id`/unregistered `redirect_uri` → **`400` JSON** `{error:"invalid_client", error_description}` (never redirects to an unvalidated uri).
- Bad `response_type` → `400` JSON `{error:"unsupported_response_type"}`.
- Missing/`!=S256` PKCE → `302 redirect_uri?error=invalid_request&...&state=`.

Errors use `400` JSON **before** `redirect_uri` is validated, and a `302` redirect with
`?error=&error_description=&state=` **after** it is known-good.

### `POST /auth/oauth/token` — code → tokens

Request (JSON):
```json
{ "code": "<one-time auth code>", "client_id": "<client_id>", "code_verifier": "<pkce verifier>" }
```
- The `code` is single-use. `client_id` must match the app the code was minted for.
- `code_verifier` is required for codes minted via `/auth/authorize` (PKCE-bound).
- No `client_secret` — consumers are public PKCE clients.

Response `200`:
```json
{ "access_token": "<jwt>", "refresh_token": "<jwt>", "token_type": "bearer", "expires_in": 900 }
```
`expires_in` is the **access** token lifetime in seconds. Errors → `400` with a message.

### `POST /auth/token/refresh` — rotate tokens

Request `{ "refresh_token": "<jwt>" }` → Response `200` same shape as above, with a **new
pair**. Refresh tokens **rotate**: the old one is revoked on each refresh. Presenting an
**already-revoked** refresh token is treated as a reuse/theft event — the IdP revokes
**all** of that user's refresh tokens and returns `401`. A token that is unknown (not in
the store) or fails signature/type validation simply returns `401` (no revoke-all). So a
consumer must persist and use only the most recent refresh token, and coalesce concurrent
refreshes.

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

`POST` only (so it cannot be triggered by cross-site GET navigation). Optional body
`{ "post_logout_redirect_uri": "...", "client_id": "..." }`. Ends the shared IdP session,
revokes all of the user's refresh tokens, clears the session cookie. If
`post_logout_redirect_uri` is supplied and is a registered redirect uri of some active
app → `302` there (open-redirect guarded); otherwise `200 {message}`. Already-issued
access tokens stay valid until expiry. This is the cross-app logout; per-app token revoke
is `/auth/token/revoke`.

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
| `aud` | the app's `client_id` (present when issued with one) |
| `scopes` | `["admin"]` for superusers else `["user"]` (present when non-empty) |

**Refresh token** (30 days): `sub`, `iss`, `iat`, `exp` (+30d), `jti`, `type:"refresh"`,
`aud`. No `email`/`scopes`. Stored server-side (hashed) for rotation + reuse detection.

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
