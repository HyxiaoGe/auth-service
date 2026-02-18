# Sean Auth Service

统一认证授权服务 —— 为所有项目提供统一的登录、注册、OAuth 社交登录、JWT 签发与验证。

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
     │  • 邮箱密码登录          │
     │  • Google / GitHub OAuth│
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

### Python 后端 (pip install)

```python
from auth import JWTValidator, require_auth

validator = JWTValidator(jwks_url="http://localhost:8100/.well-known/jwks.json")

app = FastAPI()
app.add_middleware(validator.middleware)

@app.get("/protected")
async def protected(user=Depends(require_auth)):
    return {"user_id": user.sub, "app": user.aud}
```

### 前端 (Next.js / React)

```typescript
// 跳转到统一登录页
window.location.href = `${AUTH_URL}/login?client_id=YOUR_APP_ID&redirect_uri=${CALLBACK_URL}`

// 登录成功后回调拿到 tokens
const { access_token, refresh_token } = await response.json()
```

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /auth/register | 邮箱密码注册 |
| POST | /auth/login | 邮箱密码登录 |
| GET  | /auth/oauth/google | Google OAuth 跳转 |
| GET  | /auth/oauth/google/callback | Google OAuth 回调 |
| GET  | /auth/oauth/github | GitHub OAuth 跳转 |
| GET  | /auth/oauth/github/callback | GitHub OAuth 回调 |
| POST | /auth/token/refresh | 刷新 Access Token |
| POST | /auth/token/revoke | 撤销 Refresh Token |
| GET  | /auth/userinfo | 获取当前用户信息 |
| GET  | /.well-known/jwks.json | JWKS 公钥端点 |
| GET  | /admin/apps | 查看接入应用列表 |
| POST | /admin/apps | 注册新应用 |
| GET  | /admin/login-logs | 查看登录日志 |

## 技术栈

- **FastAPI** + Uvicorn
- **PostgreSQL** + SQLAlchemy 2.0 (async)
- **Redis** (Token 黑名单 & 缓存)
- **Alembic** (数据库迁移)
- **RS256** (非对称 JWT 签名)
- **Docker Compose** 一键部署
