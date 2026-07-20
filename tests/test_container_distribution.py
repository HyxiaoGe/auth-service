"""公共容器发行配置的静态供应链约束。"""

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_container_workflow_pins_actions_and_publishes_hardened_multiarch_image():
    workflow = (ROOT / ".github/workflows/container.yml").read_text()
    action_references = re.findall(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", workflow, re.MULTILINE)

    assert action_references
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_references)
    assert "linux/amd64,linux/arm64" in workflow
    assert "packages: write" in workflow
    assert "attestations: write" in workflow
    assert "provenance: mode=max" in workflow
    assert "sbom: true" in workflow
    assert "ghcr.io/hyxiaoge/auth-service" in workflow
    pr_job = workflow.split("  pr-image:", 1)[1].split("  publish:", 1)[0]
    assert "packages: write" not in pr_job
    assert "attestations: write" not in pr_job
    assert "id-token: write" not in pr_job


def test_public_dockerfile_is_non_root_and_uses_selective_copy():
    dockerfile = (ROOT / "Dockerfile").read_text()

    assert re.search(r"FROM python:3\.12-slim@sha256:[0-9a-f]{64} AS builder", dockerfile)
    assert re.search(r"FROM python:3\.12-slim@sha256:[0-9a-f]{64} AS runtime", dockerfile)
    assert "USER auth" in dockerfile
    assert "COPY . ." not in dockerfile
    assert 'org.opencontainers.image.source="https://github.com/HyxiaoGe/auth-service"' in dockerfile


def test_bundled_dependency_images_are_digest_pinned():
    compose = (ROOT / "compose.yaml").read_text()

    assert re.search(r"image: postgres:16-alpine@sha256:[0-9a-f]{64}", compose)
    assert re.search(r"image: redis:7-alpine@sha256:[0-9a-f]{64}", compose)


def test_maintainer_deploy_always_selects_dev_compose():
    workflow = (ROOT / ".github/workflows/deploy.yml").read_text()
    compose_commands = re.findall(r"docker compose[^\n]*", workflow)

    assert compose_commands
    assert all("-f docker-compose.yml" in command for command in compose_commands)
