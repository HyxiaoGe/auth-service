"""部署必须在新应用接流量前用同一镜像完成数据库迁移。"""

from pathlib import Path


def _workflow() -> str:
    return (Path(__file__).parents[1] / ".github/workflows/deploy.yml").read_text()


def test_deploy_builds_migrates_then_switches_without_rebuild():
    workflow = _workflow()
    deploy_sequence = workflow.split("# 先构建新镜像，再迁移，最后切换服务。", 1)[1]
    build = "docker compose build auth"
    migrate = "docker compose run --rm --no-deps auth alembic upgrade head"
    switch = "docker compose up -d --no-build auth"

    assert build in deploy_sequence
    assert migrate in deploy_sequence
    assert switch in deploy_sequence
    assert deploy_sequence.index(build) < deploy_sequence.index(migrate) < deploy_sequence.index(switch)
    assert "docker compose up -d --build" not in workflow


def test_migration_failure_exits_before_new_service_switch_and_rollback_does_not_downgrade():
    workflow = _workflow()
    assert 'if ! docker compose run --rm --no-deps auth alembic upgrade head; then' in workflow
    assert "数据库迁移失败，保持旧容器继续服务" in workflow
    assert "数据库约束向后兼容，回滚应用时不执行 alembic downgrade" in workflow
    assert "alembic downgrade" not in workflow.replace(
        "数据库约束向后兼容，回滚应用时不执行 alembic downgrade",
        "",
    )
