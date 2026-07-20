# Auth Service

[![Pull Request CI](https://github.com/HyxiaoGe/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/HyxiaoGe/auth-service/actions/workflows/ci.yml)
[![CodeQL](https://github.com/HyxiaoGe/auth-service/actions/workflows/codeql.yml/badge.svg)](https://github.com/HyxiaoGe/auth-service/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

可自托管的多应用统一认证服务，提供 Google / GitHub 登录、无密码邮箱验证码登录、
Authorization Code + PKCE、RS256 JWT/JWKS、Refresh Token 轮换与跨应用 SSO 会话。

> 本项目提供自己的认证协议与端点契约，不宣称兼容 OpenID Connect。接入前请以
> [认证契约](docs/AUTH_CONTRACT.md) 为准。

## 架构

```text
┌──────────────────────┐
│ Web / Desktop Clients│
└──────────┬───────────┘
           │ Authorization Code + PKCE
           ▼
┌───────────────────────────────────────────┐
│ Auth Service (FastAPI)                    │
│                                           │
│ • Google / GitHub 登录                    │
│ • 无密码邮箱验证码注册 / 登录             │
│ • RS256 JWT 签发、JWKS 发布               │
│ • Refresh Token 轮换、撤销与 SSO 会话     │
│ • 多应用与登录审计                        │
└──────────────┬─────────────────┬──────────┘
               │                 │
               ▼                 ▼
        ┌────────────┐     ┌────────────┐
        │ PostgreSQL │     │   Redis    │
        │ 用户与审计 │     │ 会话与限流 │
        └────────────┘     └────────────┘
               │
               │ RS256 JWT / JWKS
               ▼
        ┌────────────────┐
        │ Business APIs  │
        └────────────────┘
```

## 快速开始

本地自托管使用独立的 `docker-compose.local.yml`。它会创建自己的 PostgreSQL、Redis、
数据库迁移任务和 Auth Service，不依赖任何现有 Docker 网络或其他项目。

要求：Docker Engine 与 Docker Compose v2。

```bash
# 1. 克隆项目
git clone https://github.com/HyxiaoGe/auth-service.git
cd auth-service

# 2. 创建本地配置
cp .env.example .env

# 3. 生成仅用于本地数据库的随机密码，将结果写入 .env 的 POSTGRES_PASSWORD
openssl rand -hex 32

# 4. 构建镜像并生成 JWT RSA 密钥（keys/ 已被 git 忽略；重复执行会拒绝覆盖）
docker compose -f docker-compose.local.yml run --rm --build keygen

# 5. 构建并启动；数据库迁移会在 auth 启动前自动执行
docker compose -f docker-compose.local.yml up -d --build

# 6. 查看状态
docker compose -f docker-compose.local.yml ps
curl http://localhost:8100/health

# 7. 可选：创建首个管理员和示例应用（不会生成固定密码）
AUTH_ADMIN_EMAIL=admin@example.com \
  docker compose -f docker-compose.local.yml exec -e AUTH_ADMIN_EMAIL auth \
  python scripts/init_admin.py
```

默认配置不会启用 Google、GitHub、邮箱验证码或内部账密入口，因此无需真实第三方凭据
也能启动基础服务、查看 OpenAPI 和 JWKS。启用登录方式、配置反向代理以及生产加固请见
[自托管指南](docs/SELF_HOSTING.md)。

服务启动后：

- API 文档：<http://localhost:8100/docs>
- 健康检查：<http://localhost:8100/health>
- JWKS：<http://localhost:8100/.well-known/jwks.json>

现有 `docker-compose.yml` 保留为项目维护者的 dev 部署清单；第三方本地启动请始终显式使用
`docker-compose.local.yml`。

## 业务项目接入

新应用接入分为三步：注册 `client_id`、接入客户端 SDK、实现登录回调。完整步骤见
[接入指南](docs/ONBOARDING.md)，端点与 Token 契约见
[认证契约](docs/AUTH_CONTRACT.md)，可复制示例见 [`examples/`](examples)。

### Python 后端

仓库内提供 [auth-client](auth-client)：

```bash
pip install "auth-client[fastapi] @ git+https://github.com/HyxiaoGe/auth-service.git@auth-client-v0.2.1#subdirectory=auth-client"
```

```python
from auth import JWTValidator

validator = JWTValidator(
    jwks_url=f"{AUTH_URL}/.well-known/jwks.json",
    issuer=AUTH_URL,
    audience=CLIENT_ID,
    require_token_type="access",
)
user = validator.verify(token)
```

业务 API 必须校验 `issuer`、本应用的 `audience` 和 `type=access`，不能仅验证签名。
完整模式见 [FastAPI 接入示例](examples/backend_fastapi_integration.py)。

### Next.js / React 前端

```bash
npm install git+https://github.com/HyxiaoGe/auth-client-web.git#v0.2.0
```

```typescript
import { configure, handleCallback, login, silentLogin } from "auth-client-web"

configure({
  authUrl: AUTH_URL,
  clientId: CLIENT_ID,
  redirectUri: `${origin}/auth/callback`,
})
```

启动时可使用 `silentLogin()` 探测已有 SSO 会话；登录回调页调用 `handleCallback()` 完成
`state` 校验与授权码换 Token。完整模式见
[前端 SSO 接入示例](examples/frontend_sso_integration.ts)。

## 核心端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/auth/authorize` | Authorization Code + PKCE 授权入口 |
| GET | `/auth/capabilities` | 查询指定应用与 Origin 可用的登录能力 |
| POST | `/auth/email/headless/start` | 创建邮箱验证码授权事务 |
| POST | `/auth/email/headless/send` | 发送邮箱验证码 |
| POST | `/auth/email/headless/verify` | 验证邮箱验证码并返回一次性授权码 |
| POST | `/auth/oauth/token` | 使用授权码与 PKCE verifier 换取 Token |
| GET | `/auth/oauth/google` | 发起 Google 登录 |
| GET | `/auth/oauth/github` | 发起 GitHub 登录 |
| POST | `/auth/token/refresh` | 轮换 Refresh Token 并签发新 Token |
| POST | `/auth/token/revoke` | 撤销 Refresh Token |
| POST | `/auth/logout` | 结束 SSO 会话 |
| GET | `/auth/userinfo` | 获取当前用户信息 |
| GET | `/.well-known/jwks.json` | 发布 JWT 验签公钥 |
| GET | `/health` | 进程健康检查 |

管理端点、完整请求字段和错误语义见 [认证契约](docs/AUTH_CONTRACT.md)。

## 邮箱验证码登录

邮箱验证码支持新用户无密码注册与现有用户登录；相同规范化邮箱会复用统一用户身份。
该能力默认关闭。启用时至少需要：

- `EMAIL_LOGIN_ENABLED=true` 与不少于 32 字符的 `EMAIL_CODE_PEPPER`
- SMTP 或 Resend 投递配置
- 已注册且回调地址、CORS Origin 均精确匹配的应用
- 弹窗 JSON 流程还需 `EMAIL_HEADLESS_LOGIN_ENABLED=true`

生产 HTTPS 环境还必须配置精确的受信代理 CIDR。详细安全约束见
[自托管指南](docs/SELF_HOSTING.md#启用邮箱验证码登录)。

## 技术栈

- FastAPI + Uvicorn
- PostgreSQL + SQLAlchemy 2.0（async）
- Redis（SSO 会话、授权事务、限流与撤销状态）
- Alembic 数据库迁移
- RS256 JWT / JWKS
- Docker Compose

## 开发验证

```bash
python -m pip install -r requirements-dev.txt
python -m pip install -e "./auth-client[fastapi]"
python -m pytest -q tests auth-client/tests
ruff check .
```

架构与编码约定分别见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 和
[docs/CODING_CONVENTIONS.md](docs/CODING_CONVENTIONS.md)。
