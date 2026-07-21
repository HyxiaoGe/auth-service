# Onboarding a New App

How to add a new application to the SSO ecosystem: register a `client_id`, install the
shared SDKs, wire login + callback, and verify. Once registered and wired, your app joins
single sign-on automatically — a user already logged into another app lands in yours
logged in.

For the underlying HTTP/token contract see [AUTH_CONTRACT.md](./AUTH_CONTRACT.md).
For runnable starting points see [`examples/`](../examples).

`${AUTH_URL}` below is your Auth Service base url (dev default `http://localhost:8100`).

## 1. Register a `client_id`

A consumer app is a row in the `applications` table, created through the admin API. The
server generates the `client_id` (and a `client_secret`); you supply a name and the
**exact** redirect uris your app will use.

Prerequisites (operator, once): the IdP is running with migrations applied and an admin
user exists. `scripts/init_admin.py` requires an explicit `AUTH_ADMIN_EMAIL`, creates no
fixed password, and can register the first sample app. The same normalized email becomes
the administrator when it later signs in through an enabled provider. See
[SELF_HOSTING.md](./SELF_HOSTING.md#4-创建首个管理员和应用).

Get an admin access token (log in as a superuser), then:

```bash
curl -X POST ${AUTH_URL}/admin/apps \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "description": "what it does",
    "redirect_uris": [
      "http://localhost:3000/auth/callback",
      "https://myapp.example.com/auth/callback"
    ]
  }'
```

Response (the `client_secret` is shown **once** and never again):

```json
{ "client_id": "app_xxxxxxxxxxxxxxxx", "client_secret": "<shown once>", "name": "My App", ... }
```

Save the `client_id`. Notes:
- **`redirect_uris` is an exact-match allowlist** — no wildcards. List every concrete
  callback url (each environment's). The SSO callback path used by the frontend SDK is
  `/<your-app-origin>/auth/callback`.
- The browser SSO flow is PKCE-based and does **not** use `client_secret`. Keep the secret
  out of the browser; a backend only needs it if you later add confidential-client flows
  (none today).
- To add a redirect uri later, update the app (same admin API). There is no
  `client_secret` retrieval — re-create the app if you lose it.

## 2. Backend integration (Python / FastAPI)

Install the shared validator SDK:

```bash
pip install "auth-client[fastapi]==0.3.0"
```

Configure one validator from env and expose a thin `get_current_user` that returns **your
own** user type (not the SDK's). The SDK only verifies the JWT — fetching `/auth/userinfo`
and upserting a local user row are your app's job. See
[`examples/backend_fastapi_integration.py`](../examples/backend_fastapi_integration.py)
for the full pattern; the essentials:

```python
from auth_service_client import JWTValidator

validator = JWTValidator(
    jwks_url=f"{AUTH_SERVICE_URL}/.well-known/jwks.json",
    issuer=AUTH_SERVICE_URL,
    audience=AUTH_SERVICE_CLIENT_ID,   # your client_id
    require_token_type="access",
)
```

Env vars (recommended names):

```
AUTH_SERVICE_URL=http://localhost:8100
AUTH_SERVICE_CLIENT_ID=app_xxxxxxxxxxxxxxxx
# AUTH_SERVICE_JWKS_URL=  # optional; defaults to ${AUTH_SERVICE_URL}/.well-known/jwks.json
```

## 3. Frontend integration (Next.js / React)

Install the framework-neutral browser SDK (it builds itself on install):

```bash
npm install git+https://github.com/HyxiaoGe/auth-client-web.git#v0.2.0
```

Wire four pieces (see
[`examples/frontend_sso_integration.ts`](../examples/frontend_sso_integration.ts)):

1. **`configure()` once at startup** with your `authUrl`, `clientId`, and a `redirectUri`
   of `${origin}/auth/callback`.
2. **Silent SSO probe on load** — call `silentLogin()` when there is no local token (and
   you are not on the callback route). This is the SSO win: it redirects to
   `/auth/authorize?prompt=none` and comes back either logged in or `login_required`.
3. **Callback page at `/auth/callback`** — call `handleCallback()`, which validates
   `state`, exchanges the code, and stores tokens; then route the user back.
4. **Login UI** — call `login('google')` / `login('github')` for interactive sign-in.

For API calls, use the SDK's `fetchWithAuth()` (injects the Bearer token and refreshes on
401), or call `getAccessToken()` yourself if you need a custom fetch wrapper.

Env vars (recommended names):

```
NEXT_PUBLIC_AUTH_URL=http://localhost:8100
NEXT_PUBLIC_AUTH_CLIENT_ID=app_xxxxxxxxxxxxxxxx
```

## 4. Verify

- [ ] `GET ${AUTH_URL}/.well-known/jwks.json` is reachable from your backend.
- [ ] Every callback url your app uses is in the app's `redirect_uris` (exact match).
- [ ] Interactive login: `login('google')` → consent → lands back on `/auth/callback` →
      redirected into the app, authenticated.
- [ ] Silent SSO: with a live session from another app, loading your app logs you in with
      no login screen; with no session, `prompt=none` returns `login_required` and you
      fall back to interactive login (no error UI).
- [ ] Protected backend route accepts a real access token and rejects: a missing token, an
      expired token, a token for a different `client_id` (audience), and a refresh token.
- [ ] Token refresh works across the 15-minute access-token boundary without a re-login.
- [ ] Logout ends the session and a subsequent protected call is rejected.

## 5. Going to production

- HTTPS everywhere; register HTTPS `redirect_uris`.
- Point `AUTH_SERVICE_URL` / `NEXT_PUBLIC_AUTH_URL` at the production IdP and pin the SDK
  installs to a tag or commit rather than a moving branch.
- Confirm `issuer`, `audience`, and `require_token_type` are set on the backend validator
  (see [AUTH_CONTRACT.md → Verifying tokens](./AUTH_CONTRACT.md#verifying-tokens-backend-requirements)).
