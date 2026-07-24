"""WO-9 invariant: the managed layer (actenon-cloud) is genuinely optional.

Fable 5 Part 3A invariant #1: "The kernel never depends on Cloud. Cloud
may depend on the kernel." This test makes the "optional" claim
executable by asserting:

  1. No runtime module under actenon/ imports anything cloud-related.
  2. No runtime module hardcodes an actenon-cloud or *.actenon.cloud URL.
  3. No runtime module defaults an env var to a hosted endpoint.

If any of these are false, the kernel has a hidden cloud dependency and
the "optional" claim is false.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_SOURCE = REPO_ROOT / "actenon"

# Patterns that indicate a cloud dependency.
CLOUD_IMPORT_PATTERNS = frozenset({
    "actenon_cloud",
    "actenon_cloud_config",
    "action_control_plane",
    "app",  # the cloud's app module
})

CLOUD_URL_PATTERNS = [
    re.compile(r"actenon-cloud"),
    re.compile(r"\.actenon\.cloud"),
    re.compile(r"cloud\.actenon\."),
]

# Env var names that, if defaulted to a hosted URL, would be a hidden
# cloud dependency.
HOSTED_ENDPOINT_DEFAULTS = [
    re.compile(r"https?://.*actenon.*\.cloud", re.IGNORECASE),
    re.compile(r"https?://cloud\.actenon", re.IGNORECASE),
]


def _find_kernel_python_files() -> list[Path]:
    files = []
    for p in KERNEL_SOURCE.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        files.append(p)
    return files


def _extract_imports(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                roots.add(node.module.split(".")[0])
    return roots


class TestCloudIsOptional:
    """The kernel must not have any hidden cloud dependency."""

    def test_no_cloud_imports(self):
        """No runtime module imports any cloud-related package."""
        files = _find_kernel_python_files()
        violations: list[str] = []

        for filepath in files:
            source = filepath.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=str(filepath))
            except SyntaxError:
                continue

            imports = _extract_imports(tree)
            forbidden = imports & CLOUD_IMPORT_PATTERNS
            if forbidden:
                rel = filepath.relative_to(REPO_ROOT)
                violations.append(f"{rel}: imports cloud packages: {sorted(forbidden)}")

        if violations:
            pytest.fail(
                "Cloud dependency detected — the kernel imports cloud packages:\n  "
                + "\n  ".join(violations)
            )

    def test_no_hardcoded_cloud_urls(self):
        """No runtime module hardcodes an actenon-cloud or *.actenon.cloud URL."""
        files = _find_kernel_python_files()
        violations: list[str] = []

        for filepath in files:
            source = filepath.read_text(encoding="utf-8")
            for pattern in CLOUD_URL_PATTERNS:
                matches = pattern.findall(source)
                if matches:
                    rel = filepath.relative_to(REPO_ROOT)
                    violations.append(f"{rel}: contains cloud URL pattern: {matches}")

        if violations:
            pytest.fail(
                "Cloud URL detected — the kernel hardcodes cloud endpoints:\n  "
                + "\n  ".join(violations)
            )

    def test_no_hosted_endpoint_defaults(self):
        """No env var defaults to a hosted actenon.cloud endpoint.

        This catches patterns like:
          os.environ.get("ACTENON_EVIDENCE_URL", "https://cloud.actenon.dev/...")
        which would silently route to the managed plane unless the operator
        explicitly overrides.
        """
        files = _find_kernel_python_files()
        violations: list[str] = []

        for filepath in files:
            source = filepath.read_text(encoding="utf-8")
            for pattern in HOSTED_ENDPOINT_DEFAULTS:
                matches = pattern.findall(source)
                if matches:
                    rel = filepath.relative_to(REPO_ROOT)
                    violations.append(f"{rel}: defaults to hosted endpoint: {matches}")

        if violations:
            pytest.fail(
                "Hosted endpoint default detected — the kernel defaults to a "
                "cloud endpoint:\n  " + "\n  ".join(violations)
            )
