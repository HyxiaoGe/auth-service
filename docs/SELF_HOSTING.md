# 自托管指南

本文说明如何使用版本化 GHCR 镜像或本地源码启动 Auth Service，以及从本地开发迁移到生产
环境前必须完成的配置。完整认证端点语义见 [AUTH_CONTRACT.md](AUTH_CONTRACT.md)。

## 本地启动

### 1. 准备配置

```bash
cp .env.example .env
openssl rand -hex 32
```

将生成的 64 位十六进制字符串写入 `.env` 的 `POSTGRES_PASSWORD`。示例文件中的
`replace-with-...` 只是占位符，不能用于共享环境或生产环境。

默认 `COMPOSE_PROFILES=bundled`，会启动独立 PostgreSQL 与 Redis。所有登录提供方保持关闭，
因此基础服务启动不需要 Google、GitHub、SMTP 或 Resend 凭据。

若不使用默认 `.env` 文件名，必须让 Compose 插值与容器注入读取同一个文件：

```bash
AUTH_ENV_FILE=production.env docker compose --env-file production.env up -d
```

只设置 `AUTH_ENV_FILE` 不会改变 Compose 自身的变量插值来源。

### 2. 一次启动

```bash
docker compose up -d
docker compose ps
curl http://localhost:8100/health
```

Compose 会拉取 `.env` 中 `AUTH_SERVICE_IMAGE` 指向的固定版本，并按以下顺序执行：

1. 启动内置 PostgreSQL 与 Redis（外部模式则跳过）；
2. 唯一的 `bootstrap` 任务生成或验证 JWT 密钥，等待依赖就绪并执行 `alembic upgrade head`；
3. 仅在初始化成功后启动 Auth Service，并用容器内 `/health/ready` 检查依赖。

首次启动会在命名卷 `auth_keys` 中以 `0600` 权限创建私钥。后续启动只在公私钥完整、有效且
匹配时复用；缺失一个文件、权限过宽、内容无效或密钥不匹配都会安全失败，绝不覆盖现有文件。
需要轮换密钥时，应先设计旧公钥兼容窗口并备份当前密钥，不要删除卷后直接重启。

私钥不会写入源码目录或镜像；业务服务只需要通过 JWKS 获取公钥。

PostgreSQL 与 Redis 没有发布到宿主机端口；Auth Service 默认只绑定
`127.0.0.1:8100`。数据库、Redis 与 JWT 密钥都保存在命名卷中。

### 3. 从源码构建（可选）

```bash
docker compose -f compose.yaml -f docker-compose.build.yml up -d --build
```

该覆盖文件只把 `bootstrap` 与 `auth` 改为构建当前目录，其余启动拓扑和安全检查保持一致。
日常自托管建议继续使用版本化 GHCR 镜像，便于准确回滚。

### 4. 使用外部 PostgreSQL 与 Redis（可选）

将 `.env` 改为：

```dotenv
COMPOSE_PROFILES=
DATABASE_URL=postgresql+asyncpg://user:url-encoded-password@db.example:5432/auth_service
DATABASE_URL_SYNC=postgresql://user:url-encoded-password@db.example:5432/auth_service
REDIS_URL=rediss://user:url-encoded-password@cache.example:6379/0
```

`COMPOSE_PROFILES` 留空后不会创建内置 PostgreSQL 与 Redis；`bootstrap` 会等待外部依赖并执行
迁移。数据库密码中的 `@`、`:`、`/`、`#` 等保留字符必须 URL 编码。外部数据库账号必须拥有
执行 Alembic 迁移所需的 schema 权限。

### 5. 直接消费容器镜像（不克隆源码）

镜像不包含 PostgreSQL 或 Redis。先准备可从容器网络访问的外部依赖，并创建 `auth.env`：

```dotenv
APP_ENV=production
APP_DEBUG=false
AUTH_BASE_URL=https://auth.example.com
CORS_ORIGINS=https://app.example.com
DATABASE_URL=postgresql+asyncpg://user:url-encoded-password@db.example:5432/auth_service
DATABASE_URL_SYNC=postgresql://user:url-encoded-password@db.example:5432/auth_service
REDIS_URL=rediss://user:url-encoded-password@cache.example:6379/0
```

然后让一次性初始化任务和长期服务共享同一个密钥卷与 Docker 网络：

```bash
docker network create auth-network
docker volume create auth_service_keys

docker run --rm \
  --network auth-network \
  --env-file auth.env \
  -v auth_service_keys:/app/keys \
  ghcr.io/hyxiaoge/auth-service:v1.1.0 \
  python -m scripts.bootstrap

docker run -d \
  --name auth-service \
  --restart unless-stopped \
  --network auth-network \
  --env-file auth.env \
  -v auth_service_keys:/app/keys:ro \
  -p 127.0.0.1:8100:8100 \
  ghcr.io/hyxiaoge/auth-service:v1.1.0

curl http://127.0.0.1:8100/health
```

请把 `auth-network` 替换为外部 PostgreSQL / Redis 可达的网络。镜像默认 UID 为 `10001`；
若改用宿主机目录挂载，目录和已有密钥必须允许该 UID 访问，且私钥权限不得向组或其他用户开放。
每次升级版本都应先运行新版本镜像的 `scripts.bootstrap`，迁移成功后再替换长期服务容器。

### 6. 创建首个管理员和应用

数据库迁移完成后，可显式指定一个邮箱作为首个管理员，并同时注册示例应用：

```bash
AUTH_ADMIN_EMAIL=admin@example.com \
  docker compose exec -e AUTH_ADMIN_EMAIL auth \
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

### 7. 日常操作

```bash
# 查看日志
docker compose logs -f auth

# 重新验证密钥、依赖并执行数据库迁移
docker compose run --rm bootstrap

# 停止服务，保留数据
docker compose down
```

JWT 私钥卷丢失会使既有 Access Token 与 Refresh Token 无法通过签名验证，但 Redis 中仍存活的
SSO session 可能继续签发新密钥下的 Token，因此这不等同于全局登出。全局登出还需要单独撤销
SSO session 或提升用户的 `auth_generation`。请将 `auth_keys` 与 PostgreSQL 一起纳入加密备份和
恢复演练。`docker compose down -v` 会同时删除 JWT 密钥、PostgreSQL 与 Redis 数据卷；它不是
普通卸载命令，只能在明确接受数据和密钥永久丢失时使用。

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

默认 `compose.yaml` 面向单机自托管，不是高可用生产编排模板。生产部署至少需要：

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

根目录 `docker-compose.yml` 使用项目维护者现有的外部 Docker 网络，只用于当前 dev 部署兼容。
它不是通用自托管入口。第三方部署应直接使用默认 `compose.yaml`，或自行编排等价的
PostgreSQL、Redis、迁移、持久 JWT 密钥卷与 Auth Service 服务。
