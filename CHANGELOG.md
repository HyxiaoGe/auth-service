# 更新日志

本文件记录项目的重要变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增

- 新增 `POST /auth/session/reconcile`，支持已打开的多个 RP 在同一浏览器中安全同步中央账户。
- access/auth-code/refresh token 与 refresh 持久记录新增浏览器 `sid` 绑定。
- HttpOnly Cookie lookup key 与 token 中公开 `sid` 使用两个独立随机值，Cookie 密钥
  永不进入 JWT、授权码、URL 或业务服务。
- 新增 `revoked_sid:{sid}` 定向撤销与显式 `POST /auth/logout/all` 全设备登出。

### 变更

- Python Auth Client 升级到 `0.3.0`，将导入包名从冲突风险较高的 `auth` 改为
  `auth_service_client`，使用唯一的 PyPI 发行名 `seanfield-auth-client`，并补齐元数据、
  类型标记、产物校验和 Trusted Publishing。

### 安全

- reconcile code 绑定 Origin、client、redirect、state、PKCE、公开 sid 与 session version，
  换票时通过 Cookie 映射复验；继任 token 成功持久化后才退休来源 sid。
- 新增严格的 `/auth/logout/session`；旧 `/auth/logout` 在缺少 session_sid 时仅安全回跳，
  避免 A 应用误撤销 Cookie 中已切换的 B 账号。
- 迁移前无 sid 的 refresh token 改为 fail closed，阻断无法被 session 登出撤销的永久轮转分支。
- 普通浏览器登出改为 sid 级撤销，避免本地旧账户误撤销当前 Cookie 中的新账户。

## [1.1.0] - 2026-07-20

### 新增

- 发布 `linux/amd64` 与 `linux/arm64` 公共 GHCR 镜像，并生成 SBOM 与构建来源证明。
- 默认 `compose.yaml` 支持修改 `.env` 后一次启动内置或外部 PostgreSQL / Redis。
- 新增安全、幂等的启动任务：首次生成 JWT 密钥，后续验证并复用，再执行数据库迁移。
- 提供源码构建覆盖文件，并保留 v1.0 自托管命令的兼容入口。

### 安全

- 公共运行镜像改为多阶段构建、最小复制范围和固定非 root 用户。
- Python、PostgreSQL 与 Redis 官方基础镜像固定到多架构 digest，并纳入 Docker Dependabot。
- JWT 密钥改存持久命名卷；残缺、不匹配、无效或权限过宽时拒绝启动且绝不覆盖。
- Authlib 运行依赖改为精确版本，减少不同构建时间的依赖漂移。

### 变更

- 项目维护者 dev 编排继续显式使用 `docker-compose.yml`，避免与第三方默认入口和跨版本回滚混淆。
- Auth Service API 版本升级为 `1.1.0`。

## [1.0.0] - 2026-07-20

### 安全

- 新部署不再由历史迁移写入固定超级管理员；已执行过该迁移的现有数据库不会自动降权，
  维护者应单独审计和处置遗留身份。
- JWT 密钥生成默认拒绝覆盖，并以 `0600` 权限创建私钥。
- GitHub Actions 固定到经过核对的完整提交 SHA，降低上游标签移动带来的供应链风险。
- 升级 PyJWT、cryptography、python-multipart 与 pytest，修复已公开的安全漏洞。

### 兼容性

- Resend 预检幂等键改用通用 `auth-service-*` 前缀；首次升级最多可能额外触发一次预检。

### 新增

- Apache License 2.0 开源许可证。
- 安全漏洞报告、贡献和社区行为规范。
- Issue 与 Pull Request 模板。
- Python 依赖和 GitHub Actions 的 Dependabot 更新配置。
- 独立的 Pull Request 代码检查工作流。
- 可独立启动 PostgreSQL、Redis、迁移和认证服务的本地 Docker Compose。

### 变更

- 管理员初始化改为显式邮箱、可选强密码，并移除固定管理员凭据和个人应用示例。
- 默认配置、架构示例与邮件幂等键改为项目中立命名。
- 内部账密兼容入口使用通用请求头，同时保留旧请求头兼容。
- SDK 接入示例改为固定版本标签，避免生产依赖移动中的默认分支。
- Python Auth Client 发布 `0.2.1`，同步提高 JWT 与密码学依赖的安全下限。
- Dependabot 仅批量合并次版本和补丁版本更新，主版本升级独立成 PR 审查。

[未发布]: https://github.com/HyxiaoGe/auth-service/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/HyxiaoGe/auth-service/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/HyxiaoGe/auth-service/releases/tag/v1.0.0
