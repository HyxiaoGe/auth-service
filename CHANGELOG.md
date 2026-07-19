# 更新日志

本文件记录项目的重要变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 安全

- 新部署不再由历史迁移写入固定超级管理员；已执行过该迁移的现有数据库不会自动降权，
  维护者应单独审计和处置遗留身份。
- JWT 密钥生成默认拒绝覆盖，并以 `0600` 权限创建私钥。

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

[未发布]: https://github.com/HyxiaoGe/auth-service/commits/main
