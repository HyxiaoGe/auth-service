# 新应用接入清单

完整、可复制的接入流程已经统一到 [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)。新项目应从
该文档开始，不需要参考 Fusion 或 Audio 的业务源码。

## 最短路径

1. 选择接入现有托管 Auth Service，或按 [SELF_HOSTING.md](SELF_HOSTING.md) 自部署；
2. 注册独立 `client_id`，登记每个环境的精确回调 URI；
3. 将对应 Web Origin 加入 Auth Service 的精确 `CORS_ORIGINS`；
4. 安装正式 SDK：

```bash
npm install auth-client-web@^0.4.0
pip install "seanfield-auth-client[fastapi]==0.3.0"
```

```python
from auth_service_client import JWTValidator, require_auth
```

5. 前端配置 `authUrl`、`clientId`、`redirectUri`，实现回调页和应用自己的登录弹窗；
6. 后端从 `auth_service_client` 导入 SDK，并同时锁定 JWKS、`issuer`、本应用
   `audience` 与 `require_token_type="access"`；
7. 回归 Google、GitHub、邮箱验证码、刷新恢复、跨应用账户对账、退出和异常 Token。

> `auth-client-web` 是无 UI 的认证 SDK。按钮、弹窗、邮箱与验证码输入框、加载态和国际化均由
> 应用实现；邮箱 headless 流程的完整调用顺序见
> [接入指南的邮箱验证码章节](INTEGRATION_GUIDE.md#5-邮箱验证码登录应用内弹窗)。

Access Token 有效期由 Auth Service 配置并通过 `expires_in` 返回，接入方不能硬编码 15 分钟、
24 分钟或 24 小时。底层端点与 Token 字段见 [AUTH_CONTRACT.md](AUTH_CONTRACT.md)。
