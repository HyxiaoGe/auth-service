"""公开分发基线不能再次引入固定身份或默认管理员权限。"""

from pathlib import Path

from app.config import Settings

REPOSITORY_ROOT = Path(__file__).parents[1]


def test_migrations_do_not_seed_a_fixed_superuser_identity():
    migrations = (REPOSITORY_ROOT / "alembic" / "versions").glob("*.py")

    for migration in migrations:
        source = migration.read_text()
        assert "UPDATE users SET is_superuser" not in source, migration.name


def test_env_example_documents_every_runtime_setting():
    documented = {
        line.split("=", 1)[0].removeprefix("# ")
        for line in (REPOSITORY_ROOT / ".env.example").read_text().splitlines()
        if "=" in line and not line.startswith("##")
    }
    runtime_settings = {name.upper() for name in Settings.model_fields}

    assert runtime_settings <= documented
