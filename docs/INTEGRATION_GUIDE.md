# 新项目接入 Auth Service

本文是新项目接入登录模块的单一入口。完成本文后，无需再阅读 Fusion 或 Audio 的业务源码。
底层字段与错误语义以 [认证契约](AUTH_CONTRACT.md) 为准；部署运维以
[自托管指南](SELF_HOSTING.md) 为准。

## 1. 先选择接入模式

### 模式 A：接入现有托管 Auth Service（自用默认）

适合组织内新增应用。认证服务、数据库、Redis、OAuth Provider 和邮件投递由现有运维方维护；
新项目只需要：

1. 请 Auth Service 管理员注册应用并提供 `client_id`；
2. 让管理员把每个环境的回调 URI 和 Web Origin 加入精确白名单；
3. 前端安装正式 npm 包，后端安装正式 PyPI 包；
4. 实现应用自己的登录 UI 和业务用户映射；
5. 按本文回归清单验收。

这种模式不要复制 Fusion/Audio 的认证源码，也不要从 Git 仓库安装 SDK。

### 模式 B：自部署 Auth Service

适合独立部署或第三方使用。先按 [自托管指南](SELF_HOSTING.md) 启动版本化 GHCR 镜像，配置
PostgreSQL、Redis、JWT 密钥、公开 `AUTH_BASE_URL`、精确 `CORS_ORIGINS`，再按需启用
Google、GitHub 和邮件投递。服务健康后，继续执行本文后续所有应用接入步骤。

自部署只改变 Auth Service 的归属，不改变 SDK 和协议：前端仍用 npm 包，Python 后端仍用
PyPI 包。

## 2. 准备应用配置

以下示例使用：

```text
AUTH_URL=https://auth.example.com
APP_ORIGIN=https://app.example.com
REDIRECT_URI=https://app.example.com/auth/callback
CLIENT_ID=app_xxxxxxxxxxxxxxxx
```

开发、测试、生产的回调 URI 必须分别登记。协议使用精确匹配，不支持通配符，也不会把
`http://localhost:3000` 与 `http://127.0.0.1:3000` 视为同一个地址。

### 2.1 注册应用

管理员使用 superuser access token 调用：

```bash
curl -X POST "${AUTH_URL}/admin/apps" \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "description": "My application",
    "redirect_uris": [
      "http://localhost:3000/auth/callback",
      "https://app.example.com/auth/callback"
    ]
  }'
```

响应中的 `client_id` 是前后端都需要的公开应用标识。`client_secret` 只显示一次，但当前浏览器
Authorization Code + PKCE 流程不使用它；不要把它放进浏览器环境变量或前端仓库。

### 2.2 配置 CORS 与 Origin

应用表保存回调 URI，`CORS_ORIGINS` 是 Auth Service 的全局精确 Origin 白名单，两者缺一不可。
管理员应将 Web Origin（不带路径）加入 Auth Service 配置，例如：

```dotenv
CORS_ORIGINS=http://localhost:3000,https://app.example.com
```

邮箱 headless 登录、会话对账和无跳转恢复还要求：

- 请求携带浏览器真实 `Origin` 和 `credentials: "include"`；
- Origin 必须等于已登记回调 URI 的 Origin；
- Origin 必须与 `AUTH_BASE_URL` **同 schemeful site**，例如 `auth.example.com` 与
  `app.example.com`；该限制同时适用于邮箱 headless、`session/reconcile` 和
  `session/resume`；
- 生产环境使用 HTTPS；Electron 自定义 scheme 或 `Origin: null` 不能使用 Web 邮箱 headless 协议。

完整的无跳转 SSO、邮箱验证码和可靠中央退出都应把 Auth Service 与业务应用部署在同一
schemeful site 的兄弟子域。不同 registrable domain 的应用即使 redirect URI 与 CORS 配置正确，
也只能使用顶层 `/authorize` 跳转流程；JSON resume/reconcile 与邮箱 headless 会被拒绝，
SameSite Cookie 也不能保证随全局 POST 登出请求发送。

## 3. 安装正式 SDK

### 前端（现代浏览器、ESM）

```bash
npm install auth-client-web@^0.4.0
```

提交 npm lockfile，保证部署可复现。包是框架无关 ESM SDK，适用于 React、Next.js、Vue 等现代
浏览器项目，但认证调用必须在客户端执行。

### Python / FastAPI 后端

```bash
pip install "seanfield-auth-client[fastapi]==0.3.1"
```

发行名是 `seanfield-auth-client`，Python import 名是 `auth_service_client`：

```python
from auth_service_client import JWTValidator, require_auth, require_scopes
```

## 4. 前端基础接入

> `auth-client-web` **不提供 UI**。登录弹窗、按钮、邮箱输入框、验证码输入框、加载态、错误提示
> 和国际化均由应用实现；SDK 负责 PKCE、state、Token 生命周期、会话恢复与安全提交。

### 4.1 启动时配置一次

```ts
import { configure, subscribe } from "auth-client-web";

configure({
  authUrl: process.env.NEXT_PUBLIC_AUTH_URL!,
  clientId: process.env.NEXT_PUBLIC_AUTH_CLIENT_ID!,
  redirectUri: `${window.location.origin}/auth/callback`,
});

const unsubscribe = subscribe((state) => {
  // 将 { user, status } 镜像到 React context、Redux、Zustand 等应用状态。
  // status 可能是 loading / synchronizing / authenticated / unauthenticated。
  updateApplicationAuthState(state);
});
```

不要在 SSR 阶段调用依赖 `window`、Web Crypto 或 Web Storage 的认证 API。迁移已有应用时可以
通过 `storageKeys` 复用旧键；新项目使用默认键即可。

### 4.2 Google / GitHub 登录与回调

登录按钮只需调用 SDK；Provider 回调地址由 Auth Service 运维方配置，不是业务应用回调：

```ts
import { login } from "auth-client-web";

await login("google", { redirectPath: "/dashboard" });
await login("github", { redirectPath: "/dashboard" });
```

业务应用必须实现已登记的 `/auth/callback` 页面：

```ts
import { handleCallback } from "auth-client-web";

const result = await handleCallback();
if (result.status === "authenticated") {
  router.replace(result.redirectPath || "/");
} else if (result.status === "unauthenticated") {
  // login_required 是无会话时的正常结果；回到登录 UI，不显示系统故障页。
  router.replace("/");
}
```

`handleCallback()` 会验证 `state`、使用 PKCE verifier 换取 Token、读取 `/auth/userinfo`，成功后
再提交本地会话。

### 4.3 启动恢复与跨应用账户同步

0.4.x 推荐优先使用无跳转 JSON 会话恢复：

```ts
import {
  AuthClientError,
  logout,
  reconcileSession,
  refresh,
  resumeSession,
  tokenStore,
} from "auth-client-web";

export async function restoreOrReconcileSession() {
  const resume = () => resumeSession({
    beforeCommit: async () => {
      await clearUserScopedApplicationState();
    },
  });
  // 这里只读取原始本地票据，不能先调用 getAccessToken()：后者在临近过期时会
  // refresh 旧账户票据，而 reconcile 必须先确认中央账户是否已经切换。
  const localToken = tokenStore().getAccessToken();
  if (!localToken) return resume();

  const reconcile = () => reconcileSession({
    beforeCommit: async ({ previousUser, user }) => {
      // 已确认中央账户变化时暂停请求、终止 SSE/WebSocket、清理旧用户数据。
      await isolateAccountSwitch(previousUser, user);
    },
  });
  let result;
  try {
    result = await reconcile();
  } catch (error) {
    if (!(error instanceof AuthClientError) || error.status !== 401) throw error;
    // 原始 access token 已过期或失效：只做一次 refresh，再重试一次 reconcile。
    // refresh 被明确拒绝会返回 null 并清理旧票据，此时从中央 Cookie 恢复。
    const refreshed = await refresh();
    if (!refreshed) return resume();
    result = await reconcile();
  }
  if (result.status === "no_session") {
    // 自用产品要求跨应用退出同步：中央 session 已消失时清理当前应用。
    // 若产品选择让本地 access token 自然存活到 exp，可以省略这段策略。
    await clearUserScopedApplicationState();
    await logout();
  }
  return result;
}
```

- 本地无 access token：`resumeSession()` 返回 `local_session`、`no_session` 或 `resumed`；
- 本地已有 access token：`reconcileSession()` 返回 `match`、`no_session` 或 `switched`；
- `no_session` 是正常降级，不应弹出错误；
- `reconcileSession()` 的 `no_session` 不会擅自删除本地票据；要求跨应用退出同步的宿主应像
  上例一样清理用户数据并执行本地 `logout()`；
- `reconcileSession()` 确认账户切换后会进入 `synchronizing` 屏障，应用必须在 `beforeCommit`
  清理用户绑定的查询缓存、草稿、敏感路由和长连接；
- SDK 不会自行启动定时器。建议在首次客户端挂载、窗口 `focus`、页面从隐藏变为可见时调用，
  并由应用做防抖；不要高频轮询。

旧式首次冷启动也可调用 `silentLogin()`，它会顶层跳转到 `prompt=none`。0.4.x 新项目优先
`resumeSession()`，只有目标 Auth Service 尚未开放 `/auth/session/resume` 时才需要回退到
`silentLogin()`。

判断本地是否已有票据时必须使用 `tokenStore().getAccessToken()`；业务请求才使用
`getAccessToken()` 或 `fetchWithAuth()` 触发按需刷新。若 raw access token 已失效，按上例只在
reconcile 返回 401 后执行一次 refresh；refresh 被明确拒绝后再走 resume。网络错误或 5xx 必须
保留现有会话并稍后重试，不能当成退出。

### 4.4 调用业务 API

```ts
import { fetchWithAuth } from "auth-client-web";

const response = await fetchWithAuth("/api/profile");
```

`fetchWithAuth()` 自动注入 Bearer token，在需要时合流刷新，并对 401 有界重试。账户切换屏障
期间不会继续发送旧身份请求。未走 SDK 的 SSE、WebSocket 和自定义请求仍须由应用自行终止。

## 5. 邮箱验证码登录（应用内弹窗）

邮箱验证码与 Google/GitHub 最终都进入相同的 Authorization Code + PKCE 换票流程；新用户会
无密码注册，现有规范化邮箱会复用统一身份。接口不会向前端泄露邮箱是否已注册。

### 5.1 检查能力

打开邮箱入口前查询：

```ts
const url = new URL(`${AUTH_URL}/auth/capabilities`);
url.searchParams.set("client_id", CLIENT_ID);
url.searchParams.set("redirect_uri", REDIRECT_URI);

const capabilities = await fetch(url, { credentials: "include" }).then((r) => r.json());
const enabled = capabilities.email_headless_login === true;
```

`email_login` 是兼容字段，当前恒为 `false`；应用应判断 `email_headless_login`。

### 5.2 准备授权事务并启动 flow

```ts
import {
  prepareAuthorization,
  completeAuthorization,
  cancelAuthorization,
} from "auth-client-web";

const authorization = await prepareAuthorization({ redirectPath: "/dashboard" });

const started = await fetch(`${AUTH_URL}/auth/email/headless/start`, {
  method: "POST",
  credentials: "include",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    client_id: authorization.clientId,
    redirect_uri: authorization.redirectUri,
    response_type: authorization.responseType,
    state: authorization.state,
    code_challenge: authorization.codeChallenge,
    code_challenge_method: authorization.codeChallengeMethod,
  }),
}).then(parseAuthResponse);
// started: { flow_id, csrf_token, expires_in, code_length }
```

每次打开登录事务都重新调用 `prepareAuthorization()`；用户关闭弹窗时调用
`cancelAuthorization(authorization.state)`。

### 5.3 发送与验证验证码

```ts
await fetch(`${AUTH_URL}/auth/email/headless/send`, {
  method: "POST",
  credentials: "include",
  headers: {
    "content-type": "application/json",
    "x-csrf-token": started.csrf_token,
  },
  body: JSON.stringify({ flow_id: started.flow_id, email }),
}).then(parseAuthResponse);

const verified = await fetch(`${AUTH_URL}/auth/email/headless/verify`, {
  method: "POST",
  credentials: "include",
  headers: {
    "content-type": "application/json",
    "x-csrf-token": started.csrf_token,
  },
  body: JSON.stringify({ flow_id: started.flow_id, code }),
}).then(parseAuthResponse);

const result = await completeAuthorization({
  authorizationCode: verified.code,
  state: verified.state,
});
// result: { status: "authenticated", user, redirectPath }
```

其中 `parseAuthResponse` 应先检查 `response.ok`，再按稳定的 `error` 字段处理：

- `invalid_code`：验证码错误、过期或尝试次数耗尽；
- `rate_limited`：遵守响应 `retry_after` 或 `Retry-After`，禁用倒计时内的重发按钮；
- `interaction_expired`：取消本地事务并重新开始；
- `origin_not_allowed` / `invalid_interaction`：检查 Origin、Cookie、CSRF 和部署配置；
- `delivery_unavailable`：隐藏邮箱入口或提示稍后再试。

`/send` 返回 202 只表示请求被接受，不代表账户存在或邮件已投递。不要根据响应文案区分新老用户。

## 6. 退出登录

```ts
import { logout } from "auth-client-web";

// 只退出当前应用：撤销本应用 refresh token 并清理本地会话。
await logout({ redirectTo: "/" });

// 退出当前中央浏览器 session，使已接入的应用同步收敛到未登录。
await logout({ global: true, postLogoutRedirectUri: REDIRECT_URI });
```

全局退出会通过顶层 POST 携带 access token 的公开 `sid`，Auth Service 将它与 HttpOnly Cookie
中的真实 session 精确匹配后才撤销。`postLogoutRedirectUri` 必须是本应用已登记的回调 URI。

## 7. 后端验签与本地用户

业务 API 只接受 access token。FastAPI 示例：

```python
import os

from auth_service_client import JWTValidator, require_auth, require_scopes
from fastapi import Depends, FastAPI

auth_url = os.environ["AUTH_SERVICE_URL"].rstrip("/")
client_id = os.environ["AUTH_SERVICE_CLIENT_ID"]

validator = JWTValidator(
    jwks_url=f"{auth_url}/.well-known/jwks.json",
    issuer=auth_url,
    audience=client_id,
    require_token_type="access",
    cache_ttl=300,
)

app = FastAPI()

@app.get("/me")
async def me(user=Depends(require_auth(validator))):
    return {"id": user.sub, "email": user.email, "scopes": user.scopes}

@app.get("/admin")
async def admin(user=Depends(require_scopes(validator, "admin"))):
    return {"ok": True}
```

四项校验均为安全边界，不能只验签名：

1. JWKS 中匹配 `kid` 的 RS256 公钥；
2. `issuer` 精确等于当前 Auth Service 公开地址；
3. `audience` 精确等于本应用 `client_id`；
4. `require_token_type="access"`，拒绝 refresh token 访问业务接口。

SDK 返回的是认证身份，不替业务项目管理本地用户。需要业务用户表时，以稳定的 `sub` 作为
Auth Service 外部主键，按需同步 email/name/avatar；权限、套餐和业务数据仍归本项目管理。不要
单独以可变邮箱作为业务数据外键。

### 7.1 立即撤销（可选但推荐）

`seanfield-auth-client` 负责 JWT/JWKS 校验，不连接 Redis。纯 JWT 消费者在用户从别处退出后，
已签发的 access token 会继续有效到 `exp`。如果项目需要“跨应用账户切换/全设备退出后立即
拒绝旧 access token”，业务后端还必须连接 Auth Service 使用的同一个 Redis，并在 JWT 校验后、
业务处理前检查：

```text
1. token 有 sid，且 GET revoked_sid:{sid} 存在       -> 401
2. GET revoked_user:{sub} 返回退出时刻 marker，
   且 token.iat < float(marker)                       -> 401
```

`revoked_user` 比较必须保留浮点 marker 并使用严格 `<`。Redis 读取失败时记录日志并 fail-open，
退化为等待 token 自身 `exp`，不要因 Redis 短暂故障让全部认证请求返回 500。若部署不允许业务
服务访问共享 Redis，应明确接受“access token 在 `exp` 前仍可能有效”的边界。

更完整的 marker TTL 与竞态说明见
[认证契约：Session 与全设备两级撤销](AUTH_CONTRACT.md#session-与全设备两级撤销)。

Access Token 有效期由 Auth Service 环境配置，并通过 Token 响应的 `expires_in` 返回；客户端
不能假设固定为 15 分钟或 24 小时。Refresh Token 由 SDK 轮换，应用不要自行并发刷新或持久化
旧 token。

## 8. 环境变量参考

前端：

```dotenv
NEXT_PUBLIC_AUTH_URL=https://auth.example.com
NEXT_PUBLIC_AUTH_CLIENT_ID=app_xxxxxxxxxxxxxxxx
```

后端：

```dotenv
AUTH_SERVICE_URL=https://auth.example.com
AUTH_SERVICE_CLIENT_ID=app_xxxxxxxxxxxxxxxx
# 可选覆盖；默认可由 AUTH_SERVICE_URL 拼接
AUTH_SERVICE_JWKS_URL=https://auth.example.com/.well-known/jwks.json
```

不同环境使用不同应用注册或至少登记各自精确回调 URI。生产前端变量不应指向 dev Auth Service。

## 9. 上线前回归清单

### 配置与网络

- [ ] `/health` 正常，后端可访问 `/.well-known/jwks.json`。
- [ ] 每个环境的回调 URI 已精确登记，Origin 已加入精确 `CORS_ORIGINS`。
- [ ] 生产使用 HTTPS；前端 `AUTH_URL`、后端 `issuer` 指向同一公开地址。
- [ ] npm lockfile 与 Python 依赖锁记录了实际 SDK 版本。

### 登录与会话

- [ ] Google 登录、GitHub 登录分别回到 `/auth/callback`，`state`/PKCE 换票成功。
- [ ] 邮箱验证码可完成新用户注册与老用户登录；错误码、过期和重发倒计时可用。
- [ ] 刷新页面后会话和业务数据恢复正常。
- [ ] 本地无票据但存在中央 Cookie 时，`resumeSession()` 无跳转恢复；无 Cookie 时安静返回未登录。
- [ ] 两个应用登录同一账户时对账为 `match`；一个应用切换账户后，另一个应用聚焦时安全切换并
      清理旧用户业务状态。
- [ ] 当前应用退出只清本应用；按 4.3 的 `no_session` 策略接入后，全局退出会让其他应用在
      聚焦/恢复时清理本地会话并收敛到未登录。

### Token 与后端安全

- [ ] 真实 access token 能访问保护路由。
- [ ] 缺失、过期、签名错误的 token 均返回 401。
- [ ] 其他应用 audience 的 access token 被拒绝。
- [ ] refresh token 被业务保护路由拒绝。
- [ ] 需要即时退出语义时，`revoked_sid` 与 `revoked_user` 两类 marker 都会在验签后被检查。
- [ ] Access Token 到期或业务接口 401 时 SDK 只刷新/重试一次，页面无需重新登录。
- [ ] 浏览器控制台和服务日志没有 token、验证码、PKCE verifier 或敏感邮箱明文泄露。

## 10. 继续阅读

- [认证协议与端点](AUTH_CONTRACT.md)
- [自托管部署](SELF_HOSTING.md)
- [Python SDK](../auth-client/README.md)
- [完整前端示例](../examples/frontend_sso_integration.ts)
- [完整 FastAPI 示例](../examples/backend_fastapi_integration.py)
