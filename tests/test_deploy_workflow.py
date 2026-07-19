"""部署必须在新应用接流量前用同一镜像完成数据库迁移。"""

from pathlib import Path


def _workflow() -> str:
    return (Path(__file__).parents[1] / ".github/workflows/deploy.yml").read_text()


GENERATION_MIGRATION = "alembic/versions/c8d9e0f1a2b3_add_auth_generation.py"


def test_deploy_detects_auth_generation_cutover_from_previous_sha():
    workflow = _workflow()
    assert f'git diff --name-only "$previous_sha"..HEAD -- {GENERATION_MIGRATION}' in workflow
    assert "auth_generation_cutover=1" in workflow


def test_deploy_builds_stops_migrates_then_switches_for_generation_cutover():
    workflow = _workflow()
    deploy_sequence = workflow.split("# 先构建新镜像，再按迁移类型安全切换。", 1)[1]
    build = "docker compose build auth"
    stop = "docker compose stop auth"
    migrate = "docker compose run --rm --no-deps auth alembic upgrade head"
    switch = "docker compose up -d --no-build auth"

    assert build in deploy_sequence
    assert stop in deploy_sequence
    assert migrate in deploy_sequence
    assert switch in deploy_sequence
    assert deploy_sequence.index(build) < deploy_sequence.index(stop) < deploy_sequence.index(migrate)
    assert deploy_sequence.index(migrate) < deploy_sequence.index(switch)
    assert "docker compose up -d --build" not in workflow


def test_generation_migration_failure_restores_source_and_restarts_stopped_old_container():
    workflow = _workflow()
    recovery = workflow.split("recover_stopped_previous() {", 1)[1].split("rollback() {", 1)[0]
    assert "restore_source" in recovery
    assert "docker compose start auth" in recovery
    assert "http://127.0.0.1:8100/health" in recovery
    assert "docker compose build auth" not in recovery
    assert 'if ! docker compose run --rm --no-deps auth alembic upgrade head; then' in workflow
    assert "数据库迁移失败，恢复已停止的旧容器" in workflow


def test_generation_migration_success_disables_legacy_sha_rollback_on_new_container_failure():
    workflow = _workflow()
    assert 'if [ "$auth_generation_cutover" -eq 1 ] && [ "$migration_succeeded" -eq 1 ]; then' in workflow
    assert "认证代际迁移已提交，禁止回滚到不兼容旧版本" in workflow
    generation_failure = workflow.split("认证代际迁移已提交，禁止回滚到不兼容旧版本", 1)[1]
    assert "rollback" not in generation_failure.split("else", 1)[0]


def test_regular_deploy_keeps_existing_rollback_without_database_downgrade():
    workflow = _workflow()
    assert "数据库约束向后兼容，回滚应用时不执行 alembic downgrade" in workflow
    assert "alembic downgrade" not in workflow.replace(
        "数据库约束向后兼容，回滚应用时不执行 alembic downgrade",
        "",
    )
