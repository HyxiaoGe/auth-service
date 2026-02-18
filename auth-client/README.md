# Auth Client

轻量级 JWT 验证 SDK，用于接入 Auth Service 的业务项目。

## 安装

```bash
# 从本地安装 (开发阶段)
pip install -e /path/to/auth-service/auth-client[fastapi]

# 或者从 git 安装
pip install "auth-client[fastapi] @ git+https://github.com/sean/auth-service.git#subdirectory=auth-client"
```

## 快速上手

### FastAPI 项目 (3 行接入)

```python
from fastapi import FastAPI, Depends
from auth import JWTValidator, require_auth, require_scopes

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
from auth import JWTValidator

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
    issuer="http://localhost:8100",     # 可选: 验证 token 签发者
    audience="app_your_client_id",      # 可选: 验证 token 目标应用
    cache_ttl=300,                      # JWKS 缓存时间 (秒)
)
```
