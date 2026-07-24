#!/usr/bin/env python3
"""Assert the kernel's dependency direction is correct.

WO-9 invariant: the kernel may depend on actenon-protocol and nothing
else in the actenon ecosystem. Cloud, Permit, and Scan may depend on the
kernel; the kernel never depends on them.

This script reads [project].dependencies from pyproject.toml, extracts
requirements whose name starts with "actenon", and fails if the set
differs from {"actenon-protocol"}.

Optional extras and dev groups are exempt — a [cloud] extra that pulls
in a cloud SDK is fine; a runtime dependency on actenon-cloud is not.

Usage:
    python scripts/assert_dep_direction.py
    python scripts/assert_dep_direction.py --check   # same (alias for CI)

Exit codes:
    0 — dependency direction is correct
    1 — a forbidden actenon-* dependency was found
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

ALLOWED_ACTENON_DEPS = frozenset({"actenon-protocol"})


def extract_actenon_deps(deps: list[str]) -> set[str]:
    """Extract actenon-* package names from a dependency list.

    Handles:
      - "actenon-protocol>=1.1.0,<2" -> "actenon-protocol"
      - "actenon-kernel[asymmetric]>=0.1.0" -> "actenon-kernel"
      - "actenon-protocol @ git+https://..." -> "actenon-protocol"
    """
    result: set[str] = set()
    for dep in deps:
        # Strip version constraints, extras, URLs
        # Take everything before the first [ (extras), <, >, =, !, ~, @, or space
        name = dep.strip()
        for i, ch in enumerate(name):
            if ch in "[<>=!~@ ":
                name = name[:i]
                break
        name = name.strip()
        if name.startswith("actenon"):
            result.add(name)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="alias for CI")
    args = parser.parse_args()

    if not PYPROJECT.exists():
        print(f"ERROR: {PYPROJECT} not found", file=sys.stderr)
        return 2

    with open(PYPROJECT, "rb") as f:
        data = tomllib.load(f)

    runtime_deps = data.get("project", {}).get("dependencies", [])
    actenon_deps = extract_actenon_deps(runtime_deps)

    forbidden = actenon_deps - ALLOWED_ACTENON_DEPS

    if forbidden:
        print(
            f"FAIL: kernel has forbidden actenon-* runtime dependencies: "
            f"{sorted(forbidden)}",
            file=sys.stderr,
        )
        print(
            f"Allowed: {sorted(ALLOWED_ACTENON_DEPS)}",
            file=sys.stderr,
        )
        print(
            "The kernel may depend on actenon-protocol only. Cloud, Permit, "
            "and Scan may depend on the kernel; the kernel never depends on them.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: kernel runtime actenon deps = {sorted(actenon_deps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
