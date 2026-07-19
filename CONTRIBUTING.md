# 贡献指南

感谢你参与 Auth Service。提交改动前，请先阅读本指南和 [行为准则](CODE_OF_CONDUCT.md)。安全漏洞请遵循 [安全策略](SECURITY.md)，不要创建公开 Issue。

## 开始之前

- 对缺陷修复或小型改进，可直接创建 Issue 说明问题与预期行为。
- 对认证协议、数据库结构、令牌格式、权限模型或公共 API 的显著变化，请先创建 Issue 讨论兼容性与迁移方案。
- 不要提交真实密钥、令牌、账号、验证码、生产日志或包含个人数据的测试样本。

## 本地开发

项目使用 Python 3.12。建议在独立虚拟环境中安装依赖：

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
python -m pip install -e "./auth-client[fastapi]"
```

运行提交前检查：

```bash
python scripts/check_architecture.py
python -m pytest -q tests auth-client/tests
python -m ruff check .
```

若修改了代码格式，可仅对本次涉及的 Python 文件运行 `python -m ruff format <文件...>`，避免产生无关格式化改动。

## 分支与提交

- 从最新 `main` 创建主题分支，保持每个 Pull Request 聚焦一个问题。
- 提交信息建议使用 `<type>: <简短说明>`，常用类型包括 `feat`、`fix`、`docs`、`test`、`refactor` 和 `chore`。
- 不要重写其他贡献者的提交，也不要把无关重构混入安全修复或功能变更。
- 新行为应包含测试；修复缺陷时，优先添加能够复现问题的回归测试。

## Pull Request

提交 Pull Request 前，请确认：

- 已说明背景、改动范围、兼容性影响和验证方式；
- 架构检查、测试和 Ruff 检查通过；
- 新增配置已同步到示例和文档，但未包含真实凭据；
- 数据库变化包含 Alembic 迁移，并说明升级和回滚策略；
- 公共认证协议变化已考虑现有客户端和下游服务；
- 已更新相关文档与 `CHANGELOG.md` 的“未发布”部分。

维护者可能要求拆分改动、补充测试或调整迁移方案。Pull Request 获批不代表会立即发布；合并和发布由维护者根据兼容性与安全风险安排。

## 许可证

提交贡献即表示你有权提交相关内容，并同意你的贡献按本仓库的 [Apache License 2.0](LICENSE) 授权。
