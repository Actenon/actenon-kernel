"""WO-9 invariant: the kernel depends on nothing outside {actenon, actenon_protocol}.

Fable 5 Part 3B: "The kernel never depends on Cloud. Cloud may depend on
the kernel." This test makes the invariant executable using AST analysis
(not grep), catching stray imports that a declared-dependency check
cannot see.

For every non-test .py file under actenon/, this test parses the AST and
asserts that no import has a root starting with "actenon" outside the
allowed set {actenon, actenon_protocol}.

This catches:
  - import actenon_cloud
  - from actenon_permit import ...
  - import actenon_scan
  - any future actenon_* package that should not be a kernel dependency

It does NOT flag:
  - import actenon (self-imports within the package)
  - import actenon_protocol (the declared protocol dependency)
  - import actenon.submodule (relative imports within the kernel)
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_SOURCE = REPO_ROOT / "actenon"

ALLOWED_ACTENON_ROOTS = frozenset({
    "actenon",
    "actenon_protocol",
})


def _extract_actenon_imports(tree: ast.AST) -> set[str]:
    """Extract all actenon-* root package names from an AST."""
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name.startswith("actenon"):
                    roots.add(name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                name = node.module.split(".")[0]
                if name.startswith("actenon"):
                    roots.add(name)
            # Relative imports (level > 0) are within the package — skip.
    return roots


def _find_kernel_python_files() -> list[Path]:
    """Find all non-test .py files under actenon/."""
    files = []
    for p in KERNEL_SOURCE.rglob("*.py"):
        # Skip __pycache__
        if "__pycache__" in p.parts:
            continue
        files.append(p)
    return files


class TestKernelIndependence:
    """The kernel must not import any actenon-* package outside the allowed set."""

    def test_no_cloud_permit_scan_imports(self):
        """AST-based check: no actenon_* import outside {actenon, actenon_protocol}."""
        files = _find_kernel_python_files()
        assert len(files) > 0, "no kernel source files found"

        violations: list[str] = []
        for filepath in files:
            source = filepath.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=str(filepath))
            except SyntaxError as e:
                # Record but don't fail — a syntax error is a different defect
                violations.append(f"{filepath.relative_to(REPO_ROOT)}: SYNTAX ERROR: {e}")
                continue

            roots = _extract_actenon_imports(tree)
            forbidden = roots - ALLOWED_ACTENON_ROOTS
            if forbidden:
                rel = filepath.relative_to(REPO_ROOT)
                violations.append(
                    f"{rel}: imports forbidden actenon packages: {sorted(forbidden)}"
                )

        if violations:
            pytest.fail(
                "Kernel independence violation — the kernel must not depend on "
                "any actenon-* package outside {actenon, actenon_protocol}:\n  "
                + "\n  ".join(violations)
            )

    def test_violation_detection_works(self, tmp_path, monkeypatch):
        """Negative test: if we add a forbidden import, the check catches it.

        This proves the test is not vacuously passing.
        """
        # Create a temp .py file with a forbidden import and verify detection
        bad_source = "import actenon_permit\n"
        tree = ast.parse(bad_source)
        roots = _extract_actenon_imports(tree)
        forbidden = roots - ALLOWED_ACTENON_ROOTS
        assert "actenon_permit" in forbidden, "test should detect actenon_permit import"
