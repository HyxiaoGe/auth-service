# 自托管指南

本文说明如何使用仓库自带的独立 Docker Compose 启动 Auth Service，以及从本地开发迁移到
生产环境前必须完成的配置。完整认证端点语义见 [AUTH_CONTRACT.md](AUTH_CONTRACT.md)。

## 本地启动

### 1. 准备配置

```bash
cp .env.example .env
openssl rand -hex 32
```

将生成的 64 位十六进制字符串写入 `.env` 的 `POSTGRES_PASSWORD`。示例文件中的
`replace-with-...` 只是占位符，不能用于共享环境或生产环境。

默认会保持所有登录提供方关闭。基础服务启动不需要 Google、GitHub、SMTP 或 Resend 凭据。

### 2. 生成 JWT 密钥

```bash
docker compose -f docker-compose.local.yml run --rm --build keygen
```

密钥生成器会以 `0600` 权限创建私钥，并在任一目标文件已存在时直接失败，避免误操作导致
现有 JWT 与 JWKS 突变。需要轮换密钥时，应先设计旧公钥兼容窗口并备份当前密钥，不要把
重复执行本命令当作轮换流程。

命令会在本地 `keys/` 目录生成 `private.pem` 与 `public.pem`。`keys/` 已被 Git 忽略；
私钥不得提交、上传到镜像仓库或与业务服务共享。业务服务只需要通过 JWKS 获取公钥。

### 3. 启动服务

```bash
docker compose -f docker-compose.local.yml up -d --build
docker compose -f docker-compose.local.yml ps
curl http://localhost:8100/health
```

Compose 会按以下顺序执行：

1. 启动独立 PostgreSQL 与 Redis，并等待健康检查通过；
2. 运行 `alembic upgrade head`；
3. 启动 Auth Service，并用容器内 `/health/ready` 检查数据库与 Redis。

PostgreSQL 与 Redis 没有发布到宿主机端口；Auth Service 默认只绑定
`127.0.0.1:8100`。数据保存在命名卷中。

### 4. 创建首个管理员和应用

数据库迁移完成后，可显式指定一个邮箱作为首个管理员，并同时注册示例应用：

```bash
AUTH_ADMIN_EMAIL=admin@example.com \
  docker compose -f docker-compose.local.yml exec -e AUTH_ADMIN_EMAIL auth \
  python scripts/init_admin.py \
  --sample-app-name "Example Web App" \
  --sample-app-redirect-uri "http://localhost:3000/auth/callback"
```

脚本不会创建固定密码；管理员之后通过已启用的 Google、GitHub 或邮箱验证码方式登录，
规范化邮箱与 `AUTH_ADMIN_EMAIL` 相同时会复用该管理员身份。脚本只在首次创建应用时显示
`client_secret`，请立即保存且不要写入前端代码。若仅创建管理员，可加 `--skip-sample-app`。

旧系统确实需要内部账密兼容时，才在**首次创建管理员**时通过临时环境变量
`AUTH_ADMIN_PASSWORD` 提供强密码；不要把管理员密码写入 `.env`、命令历史或部署日志。
若该身份已存在，初始化脚本会拒绝覆盖密码，必须改用独立、可审计的密码轮换流程。设置
密码也不会自动开放账密登录端点。

### 5. 日常操作

```bash
# 查看日志
docker compose -f docker-compose.local.yml logs -f auth

# 重新执行数据库迁移
docker compose -f docker-compose.local.yml run --rm migrate

# 停止服务，保留数据
docker compose -f docker-compose.local.yml down
```

`docker compose ... down -v` 会删除 PostgreSQL 与 Redis 数据卷；仅在明确需要清空本地数据时使用。

本地 Compose 不会自动创建管理员或示例应用，也不会写入固定口令。应用注册与 SDK 接入流程见
[ONBOARDING.md](ONBOARDING.md)。

## 启用 Google 或 GitHub 登录

在对应平台创建 OAuth Application，并将回调地址配置为 Auth Service 暴露的回调端点：

- Google：`${AUTH_BASE_URL}/auth/oauth/google/callback`
- GitHub：`${AUTH_BASE_URL}/auth/oauth/github/callback`

然后填写对应环境变量：

```dotenv
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

没有配置凭据的提供方应保持不可用。客户端还需要使用已注册应用的精确 `client_id` 与
`redirect_uri` 发起授权。

## 启用邮箱验证码登录

邮箱验证码默认关闭。启用前生成独立 pepper：

```bash
openssl rand -hex 32
```

至少配置：

```dotenv
EMAIL_LOGIN_ENABLED=true
EMAIL_HEADLESS_LOGIN_ENABLED=true
EMAIL_CODE_PEPPER=<64 位随机十六进制字符串>
SMTP_FROM_EMAIL=login@example.com
SMTP_FROM_NAME=Auth Service
SMTP_SMOKE_RECIPIENT=delivery-check@example.com
```

再选择一种投递方式。

### SMTP

```dotenv
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=<SMTP 用户名>
SMTP_PASSWORD=<SMTP 密码>
SMTP_STARTTLS=true
SMTP_USE_SSL=false
```

端口 465 的隐式 TLS 应设置 `SMTP_USE_SSL=true`、`SMTP_STARTTLS=false`。不要在公网或生产环境
启用明文 SMTP。

### Resend

```dotenv
RESEND_API_KEY=<Resend API Key>
RESEND_MONTHLY_QUOTA=3000
RESEND_DAILY_QUOTA=100
```

配置 `RESEND_API_KEY` 后服务会使用 Resend；`SMTP_FROM_EMAIL`、`SMTP_FROM_NAME` 与
`SMTP_SMOKE_RECIPIENT` 仍用于发件身份和投递预检。

邮箱弹窗登录还要求应用的回调 URI、CORS Origin、请求 Origin 精确匹配，并且 Web Origin 与
`AUTH_BASE_URL` 满足服务契约中的 same-site 限制。不能仅通过扩大 CORS 开启该能力。

## 生产部署检查表

`docker-compose.local.yml` 面向单机本地体验，不是生产编排模板。生产部署至少需要：

- 使用 HTTPS 反向代理，并将 `AUTH_BASE_URL` 设置为最终公开地址；
- 将 `APP_ENV` 设为 `production`，关闭 `APP_DEBUG`；
- 将 JWT 私钥、数据库口令、OAuth Secret 和邮件凭据存入 Secret Manager；
- 对 PostgreSQL 与 Redis 启用备份、监控、访问控制和持久化策略；
- 只在 `TRUSTED_PROXY_CIDRS` 中填写直连反向代理的精确 CIDR；
- 以精确 Origin 配置 `CORS_ORIGINS`，不要使用通配符；
- 为每个应用登记精确回调 URI，锁定 JWT `audience`；
- 保持 `PASSWORD_AUTH_ENABLED=false`，除非存在经过审计的受控兼容需求；
- 在切换流量前执行 Alembic 迁移并检查容器内 `/health/ready`；
- 为 JWT 密钥轮换、Refresh Token 撤销和安全事件建立运维流程。

生产环境不要直接暴露 PostgreSQL、Redis 或内部 readiness 端点。

## 现有 dev Compose

根目录 `docker-compose.yml` 使用项目维护者现有的外部 Docker 网络，保留用于当前 dev 部署兼容。
它不是通用自托管入口，也不会被本地指南引用。第三方部署应基于
`docker-compose.local.yml` 或自行编排等价的 PostgreSQL、Redis、迁移与 Auth Service 服务。
