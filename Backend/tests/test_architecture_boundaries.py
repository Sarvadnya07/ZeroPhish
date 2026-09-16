"""
Architecture boundary tests.

CODEQUALITY-01 (F-11): dependency direction is currently clean but enforced
only by convention. These tests lock in the existing rules so violations fail
CI instead of accumulating silently. They assert the *current* direction —
update them deliberately when the architecture intentionally changes.

CODEQUALITY-03: The original walker never registered plain module-level
imports (it inspected the *children* of Import/ImportFrom nodes, which are
`alias` leaves — the negative validation injected a forbidden import and the
tests still passed). Rewritten around a single ast.walk with an explicit
TYPE_CHECKING-subtree check, plus self-tests so the detection machinery can
never silently regress to vacuous-pass again.
"""

from __future__ import annotations

import ast
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent


def _is_type_checking_if(node: ast.AST) -> bool:
    """True for `if TYPE_CHECKING:` / `if typing.TYPE_CHECKING:` statements."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    if isinstance(test, ast.Attribute):
        return test.attr == "TYPE_CHECKING"
    return False


def _imported_top_level_modules(node: ast.Import | ast.ImportFrom) -> set[str]:
    """Top-level module names imported by one Import/ImportFrom statement."""
    if isinstance(node, ast.Import):
        return {alias.name.split(".")[0] for alias in node.names}
    # Relative imports (level > 0) are intra-package edges, not top-level names.
    if node.level == 0 and node.module:
        return {node.module.split(".")[0]}
    return set()


def _module_imports(path: Path) -> tuple[set[str], set[str]]:
    """Return (runtime imports, typing-only imports) as top-level module names.

    Imports inside a `if TYPE_CHECKING:` subtree are reported as typing-only:
    they exist purely for static analysis and create no runtime edge.
    Imports inside try/except (optional dependencies) are runtime edges.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return set(), set()

    runtime: set[str] = set()
    typing_only: set[str] = set()

    # Single classification pass over the whole tree. TYPE_CHECKING subtrees
    # are walked separately so their imports land in typing_only; ast.walk
    # would otherwise visit those imports first and misclassify them.
    type_checking_roots = [n for n in ast.walk(tree) if _is_type_checking_if(n)]
    type_checking_nodes: set[int] = set()
    for root in type_checking_roots:
        for stmt in ast.walk(root):
            type_checking_nodes.add(id(stmt))
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                typing_only |= _imported_top_level_modules(stmt)

    for node in ast.walk(tree):
        if id(node) in type_checking_nodes:
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            runtime |= _imported_top_level_modules(node)

    return runtime, typing_only


def _backend_python_files(subdir: str) -> list[Path]:
    directory = BACKEND_DIR / subdir
    if not directory.exists():
        return []
    return sorted(p for p in directory.rglob("*.py") if "__pycache__" not in p.parts)


def _assert_no_import_from(subdir: str, forbidden: set[str], rule: str) -> None:
    offenders = []
    for path in _backend_python_files(subdir):
        runtime, _typing_only = _module_imports(path)
        # Only runtime imports create real dependency edges. TYPE_CHECKING
        # imports are annotation-only seams and are deliberately allowed.
        bad_runtime = runtime & forbidden
        if bad_runtime:
            offenders.append((path, bad_runtime))
    assert not offenders, (
        f"{rule} violated by: "
        + "; ".join(f"{p.relative_to(BACKEND_DIR)} imports {sorted(m)}" for p, m in offenders)
    )


# --------------------------------------------------------------------------
# Self-tests: the detection machinery itself must be provably non-vacuous.
# CODEQUALITY-03 addition — these would have caught the original walker bug.
# --------------------------------------------------------------------------

def _parse_imports(source: str) -> tuple[set[str], set[str]]:
    import tempfile, os

    tmp = Path(tempfile.mktemp(suffix=".py"))
    try:
        tmp.write_text(source)
        return _module_imports(tmp)
    finally:
        os.unlink(tmp)


class TestImportDetectionWorks:
    """Guard against the detector silently becoming vacuous again."""

    def test_plain_top_level_import_detected_as_runtime(self):
        runtime, typing_only = _parse_imports("from auth.models import User\n")
        assert "auth" in runtime
        assert "auth" not in typing_only

    def test_plain_import_statement_detected_as_runtime(self):
        runtime, _ = _parse_imports("import gateway\n")
        assert "gateway" in runtime

    def test_type_checking_import_detected_as_typing_only(self):
        runtime, typing_only = _parse_imports(
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from incidents.models import Incident\n"
        )
        assert "incidents" in typing_only
        assert "incidents" not in runtime

    def test_typing_dot_type_checking_attribute_guard(self):
        runtime, typing_only = _parse_imports(
            "import typing\n"
            "if typing.TYPE_CHECKING:\n"
            "    from webhooks.models import WebhookDelivery\n"
        )
        assert "webhooks" in typing_only
        assert "webhooks" not in runtime

    def test_try_except_import_counts_as_runtime(self):
        runtime, _ = _parse_imports(
            "try:\n"
            "    import sqlalchemy\n"
            "except ImportError:\n"
            "    sqlalchemy = None\n"
        )
        assert "sqlalchemy" in runtime

    def test_relative_import_is_not_top_level(self):
        runtime, _ = _parse_imports("from .base import UserRepository\n")
        assert runtime == set()

# --------------------------------------------------------------------------
# Boundary rules: assert the current dependency direction.
# --------------------------------------------------------------------------

def test_repositories_do_not_import_application_layer() -> None:
    """Repositories must not depend on gateway, routers, or services.

    Domain *models* (auth/incidents/webhooks/analytics `.models` modules) are
    shared value types and are explicitly allowed — the rule targets
    application behavior (routers, services, orchestrators), not DTOs.
    """
    forbidden = {
        "gateway",
        "tier_2",
        "tier_3",
        "ml",
    }
    _assert_no_import_from("repositories", forbidden, "repositories -> application layer")


def test_security_does_not_import_feature_modules() -> None:
    """Security is a foundation; feature modules depend on it, never the reverse."""
    forbidden = {
        "gateway",
        "auth",
        "incidents",
        "webhooks",
        "analytics",
        "awareness",
        "email_scanner",
        "vision",
        "tier_2",
        "tier_3",
        "ml",
        "repositories",
    }
    _assert_no_import_from("security", forbidden, "security -> feature modules")


def test_infrastructure_does_not_import_domain_or_application() -> None:
    """Infrastructure (DB engine/models) sits at the bottom of the graph."""
    forbidden = {
        "gateway",
        "auth",
        "incidents",
        "webhooks",
        "analytics",
        "awareness",
        "email_scanner",
        "vision",
        "repositories",
        "ml",
    }
    _assert_no_import_from("infrastructure", forbidden, "infrastructure -> domain/application")


def test_feature_routers_do_not_import_gateway() -> None:
    """Extension routers are plugged into the gateway, not the other way around."""
    for feature in ("auth", "incidents", "webhooks", "analytics", "awareness", "email_scanner", "vision"):
        _assert_no_import_from(feature, {"gateway"}, f"{feature} -> gateway")
