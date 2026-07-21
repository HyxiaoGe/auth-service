# Auth Client

轻量级 JWT 验证 SDK，用于接入 Auth Service 的业务项目。

## 安装

```bash
# 基础 JWT 校验器
pip install "seanfield-auth-client==0.3.0"

# FastAPI 依赖工厂
pip install "seanfield-auth-client[fastapi]==0.3.0"
```

需要验证尚未发布的源码时，可从仓库子目录安装：

```bash
pip install "seanfield-auth-client[fastapi] @ git+https://github.com/HyxiaoGe/auth-service.git@auth-client-v0.3.0#subdirectory=auth-client"
```

支持 Python 3.10–3.13。包内包含 `py.typed`，类型检查器可直接读取公开 API 的类型信息。

## 快速上手

### FastAPI 项目 (3 行接入)

```python
from fastapi import FastAPI, Depends
from auth_service_client import JWTValidator, require_auth, require_scopes

# 指向你部署的 Auth Service 的 JWKS 端点
validator = JWTValidator(jwks_url="http://localhost:8100/.well-known/jwks.json")

app = FastAPI()

@app.get("/public")
async def public():
    return {"message": "anyone can see this"}

@app.get("/protected")
async def protected(user=Depends(require_auth(validator))):
    return {
        "message": "you are authenticated",
        "user_id": user.sub,
        "email": user.email,
        "app": user.aud,
    }

@app.get("/admin-only")
async def admin_only(user=Depends(require_scopes(validator, "admin"))):
    return {"message": "admin access granted"}
```

### 非 FastAPI 项目 (同步验证)

```python
from auth_service_client import JWTValidator

validator = JWTValidator(jwks_url="http://localhost:8100/.well-known/jwks.json")

def verify_request(authorization_header: str):
    token = authorization_header.replace("Bearer ", "")
    user = validator.verify(token)
    print(f"User {user.sub} ({user.email}) authenticated")
    return user
```

## 配置选项

```python
validator = JWTValidator(
    jwks_url="http://localhost:8100/.well-known/jwks.json",
    issuer="http://localhost:8100",     # 可选: 验证 token 签发者 (iss)
    audience="app_your_client_id",      # 可选: 验证 token 目标应用 (aud = 你的 client_id)
    require_token_type="access",        # 可选: 拒绝 refresh token 走保护路由
    cache_ttl=300,                      # JWKS 缓存时间 (秒)
)
```

> 生产接入建议三项 (`issuer` / `audience` / `require_token_type`) 全开 ——
> IdP 不校验 `aud`，由消费方自己锁定 token 是发给本应用的。详见
> [认证契约](https://github.com/HyxiaoGe/auth-service/blob/main/docs/AUTH_CONTRACT.md)。

## 发布维护

PyPI 发布仅由仓库的 `python-client-publish.yml` 工作流处理。工作流只响应
`auth-client-v*` 标签，先运行 SDK 测试、lint、构建内容校验、`twine check` 与隔离安装
smoke，再通过 PyPI Trusted Publishing 上传；不会读取长期 PyPI API Token。

PyPI 项目需要配置以下 Trusted Publisher：

- PyPI Project：`seanfield-auth-client`
- Owner：`HyxiaoGe`
- Repository：`auth-service`
- Workflow：`python-client-publish.yml`
- Environment：`pypi`

发布前必须同步更新 `pyproject.toml` 与 `auth_service_client/__init__.py` 中的版本。标签必须
与包版本完全一致，例如 `0.3.0` 只能由 `auth-client-v0.3.0` 发布。
