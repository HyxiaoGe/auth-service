#!/usr/bin/env python3
"""Validate import dependencies between architectural layers.

Layers (from lowest to highest):
  config    - no app imports allowed
  schemas   - no app imports allowed
  database  - may import config
  models    - may import database
  utils     - may import config
  security  - may import config; deps may import security.jwt_handler
  services  - may import config, models, schemas, security, utils
  routers   - may import config, database, models, schemas, security, services, utils
  main      - may import anything

Each layer can only import from layers at the same level or below,
following the dependency rules above.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"

# Allowed app.* import targets for each layer
ALLOWED_IMPORTS: dict[str, set[str]] = {
    "config": set(),
    "schemas": set(),
    "database": {"config"},
    "models": {"database"},
    "utils": {"config"},
    "security": {"config", "security"},
    "services": {"config", "models", "schemas", "security", "services", "utils"},
    "routers": {"config", "database", "models", "schemas", "security", "services", "utils"},
    "main": {"config", "database", "models", "schemas", "security", "services", "routers", "utils"},
}


def classify_module(filepath: Path) -> str | None:
    """Determine which layer a file belongs to."""
    rel = filepath.relative_to(APP_DIR)
    parts = rel.parts

    # app/main.py
    if rel.name == "main.py" and len(parts) == 1:
        return "main"

    # app/config.py, app/database.py
    if len(parts) == 1:
        stem = rel.stem
        if stem in ALLOWED_IMPORTS:
            return stem
        return None

    # app/<layer>/...
    layer = parts[0]
    if layer in ALLOWED_IMPORTS:
        return layer
    return None


def extract_app_imports(filepath: Path) -> list[tuple[int, str]]:
    """Parse a Python file and return (line_number, imported_module) for app.* imports."""
    source = filepath.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app."):
            # Extract the first sub-module: app.<target>
            parts = node.module.split(".")
            if len(parts) >= 2:
                target = parts[1]
                imports.append((node.lineno, target))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("app."):
                    parts = alias.name.split(".")
                    if len(parts) >= 2:
                        target = parts[1]
                        imports.append((node.lineno, target))
    return imports


def check_file(filepath: Path) -> list[str]:
    """Check a single file for architecture violations."""
    layer = classify_module(filepath)
    if layer is None:
        return []

    allowed = ALLOWED_IMPORTS.get(layer, set())
    violations = []

    for lineno, target in extract_app_imports(filepath):
        if target not in allowed:
            rel_path = filepath.relative_to(APP_DIR.parent)
            violations.append(
                f"  {rel_path}:{lineno}: layer '{layer}' imports 'app.{target}' "
                f"(allowed: {sorted(allowed) if allowed else 'none'})"
            )

    return violations


def main() -> int:
    violations: list[str] = []

    for pyfile in sorted(APP_DIR.rglob("*.py")):
        if "__pycache__" in pyfile.parts:
            continue
        violations.extend(check_file(pyfile))

    if violations:
        print(f"Architecture violations found ({len(violations)}):\n")
        for v in violations:
            print(v)
        return 1

    print("Architecture check passed -- no violations found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
