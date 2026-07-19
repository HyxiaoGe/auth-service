# Sean Auth Service

统一认证授权服务 —— 为所有项目提供统一的登录、OAuth 社交登录、JWT 签发与验证。

## 架构

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│ MovieMate│  │  Prism   │  │ 项目 N   │
│  (前端)  │  │  (前端)  │  │  (前端)  │
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │
     └─────────────┼─────────────┘
                   ▼
     ┌─────────────────────────┐
     │   Sean Auth Service     │
     │   (FastAPI + PostgreSQL)│
     │                         │
     │  • 邮箱验证码登录        │
     │  • Google/GitHub 登录    │
     │  • JWT 签发 (RS256)     │
     │  • Token 刷新 / 撤销    │
     │  • 多应用管理            │
     │  • 登录审计日志          │
     └────────────┬────────────┘
                  │
     ┌────────────┼─────────────┐
     ▼            ▼             ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ MovieMate│ │  Prism   │ │ 项目 N   │
│ (后端API)│ │ (后端API)│ │ (后端API)│
│ JWT验证  │ │ JWT验证  │ │ JWT验证  │
└──────────┘ └──────────┘ └──────────┘
```

## 快速开始

```bash
# 1. 克隆项目
git clone <repo-url> && cd sean-auth

# 2. 复制环境配置
cp .env.example .env
# 编辑 .env 填入你的 Google/GitHub OAuth credentials

# 3. 生成 RSA 密钥对
python scripts/generate_keys.py

# 4. 启动服务
docker compose up -d

# 5. 运行数据库迁移
docker compose exec auth alembic upgrade head

# 6. 创建初始管理员 & 注册第一个应用
docker compose exec auth python scripts/init_admin.py
```

服务启动后:
- API 文档: http://localhost:8100/docs
- JWKS 端点: http://localhost:8100/.well-known/jwks.json

## 业务项目接入

新项目接入 SSO 分三步：注册 `client_id` → 装共享 SDK → 接登录/回调。完整步骤见
[docs/ONBOARDING.md](docs/ONBOARDING.md)，端点与 token 契约见
[docs/AUTH_CONTRACT.md](docs/AUTH_CONTRACT.md)，可复制模板见 [`examples/`](examples)。

### Python 后端 — [auth-client](auth-client)

```bash
pip install "auth-client[fastapi] @ git+https://github.com/HyxiaoGe/auth-service.git@main#subdirectory=auth-client"
```

```python
from auth import JWTValidator

validator = JWTValidator(
    jwks_url=f"{AUTH_URL}/.well-known/jwks.json",
    issuer=AUTH_URL,             # 校验签发者
    audience=CLIENT_ID,          # 校验 token 是发给本应用的（IdP 不校验 aud，消费方自己锁）
    require_token_type="access", # 拒绝 refresh token 走保护路由
)
user = validator.verify(token)   # -> AuthenticatedUser(sub, email, aud, scopes, raw_payload)
```

完整的「薄 `get_current_user` → 项目自有 user 类型」模式见
[examples/backend_fastapi_integration.py](examples/backend_fastapi_integration.py)。

### 前端 (Next.js / React) — [auth-client-web](https://github.com/HyxiaoGe/auth-client-web)

```bash
npm install git+https://github.com/HyxiaoGe/auth-client-web.git
```

```typescript
import { configure, silentLogin, login, handleCallback } from "auth-client-web"

configure({ authUrl: AUTH_URL, clientId: CLIENT_ID, redirectUri: `${origin}/auth/callback` })
// 启动时静默探测 SSO（无本地 token 时）；无会话则回落到 login('google' | 'github')
// /auth/callback 页调用 handleCallback() 校验 state、换码、存 token
```

完整接入（静默探测 + 回调页 + 受保护请求）见
[examples/frontend_sso_integration.ts](examples/frontend_sso_integration.ts)。

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | /auth/authorize | SSO 授权端点 (PKCE S256；`prompt=none` 静默登录) |
| GET  | /auth/capabilities | 当前 Origin 与指定 app 可用的认证能力；headless 需带 `client_id`、`redirect_uri` |
| POST | /auth/email/headless/start | 创建弹窗邮箱验证码授权事务 |
| POST | /auth/email/headless/send | 发送邮箱验证码（JSON） |
| POST | /auth/email/headless/verify | 验证邮箱验证码并返回一次性授权码 |
| POST | /auth/oauth/token | 授权码换 token (PKCE) |
| GET  | /auth/oauth/google | Google OAuth 跳转 |
| GET  | /auth/oauth/google/callback | Google OAuth 回调 |
| GET  | /auth/oauth/github | GitHub OAuth 跳转 |
| GET  | /auth/oauth/github/callback | GitHub OAuth 回调 |
| POST | /auth/token/refresh | 刷新 Access Token |
| POST | /auth/token/revoke | 撤销 Refresh Token |
| POST | /auth/logout | 单点登出 (结束 IdP 会话) |
| GET  | /auth/userinfo | 获取当前用户信息 |
| GET  | /.well-known/jwks.json | JWKS 公钥端点 |
| GET  | /admin/apps | 查看接入应用列表 |
| POST | /admin/apps | 注册新应用 |
| GET  | /admin/login-logs | 查看登录日志 |
| GET  | /admin/email-usage | 查看 Resend 脱敏月度用量快照（仅管理员） |

`POST /auth/register` 与 `POST /auth/login` 默认不会注册，也不会出现在 OpenAPI 中。
仅现有受控内部任务需要兼容时，才可同时配置 `PASSWORD_AUTH_ENABLED=true`、至少 32 字符的
`PASSWORD_AUTH_INTERNAL_TOKEN`、非空 `PASSWORD_AUTH_EMAIL_PREFIX` 与精确的
`PASSWORD_AUTH_EMAIL_DOMAIN`，并在请求的 `X-Fusion-Internal-Auth` 头中传入完全相同的令牌。
例如 `fusion-perf+` 与 `seanfield.org` 只允许 `fusion-perf+...@seanfield.org`。即使启用，两端点
仍不进入 OpenAPI；令牌缺失、错误或邮箱超出范围时统一返回 404，不应作为产品登录能力接入。

邮箱弹窗登录在调用
`/auth/capabilities?client_id=...&redirect_uri=...` 时才可能返回
`email_headless_login: true`。服务会重新校验数据库中的 active Application、精确回调地址、
CORS、回调 Origin 与请求 Origin，并要求该 Web Origin 与 `AUTH_BASE_URL` schemeful
same-site。兼容字段 `email_login` 固定为 `false`，无完整应用参数时 headless 也固定为
`false`。完整契约见
[docs/AUTH_CONTRACT.md](docs/AUTH_CONTRACT.md#headless-email-otp--in-app-interaction)。

邮件默认继续使用 SMTP。只有显式配置 `RESEND_API_KEY` 时才切换到 Resend
Email API，发件地址、发件名与预检收件人继续使用现有 `SMTP_FROM_EMAIL`、
`SMTP_FROM_NAME` 和 `SMTP_SMOKE_RECIPIENT`。`RESEND_MONTHLY_QUOTA` 必须是正整数；
免费计划将 `RESEND_DAILY_QUOTA` 设为正整数，无日限额的付费计划设为 `paid`。
管理员用量接口只读取成功发送响应头写入 Redis 的数字快照，不会额外请求
Resend，也不保存 API key、验证码或收件地址。

## 技术栈

- **FastAPI** + Uvicorn
- **PostgreSQL** + SQLAlchemy 2.0 (async)
- **Redis** (Token 黑名单 & 缓存)
- **Alembic** (数据库迁移)
- **RS256** (非对称 JWT 签名)
- **Docker Compose** 一键部署
