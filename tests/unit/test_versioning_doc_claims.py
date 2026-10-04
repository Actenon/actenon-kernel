"""VERSIONING.md's "Current version" block must match pyproject.toml.

It said "Kernel version: 1.0.0" through 1.1.0, 1.2.0, 1.2.1 and the 1.3.0
candidate. Each line in the block names its machine-readable source, and the
values that can drift are checked here.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10: tomli is a dev dependency there
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]


def test_current_version_block_matches_pyproject():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    text = (ROOT / "VERSIONING.md").read_text(encoding="utf-8")
    block = text.split("## Current version", 1)[1].split("\n## ", 1)[0]
    stated = re.search(r"\*\*Kernel version:\*\* `([^`]+)`", block)
    assert stated is not None, "VERSIONING.md 'Current version' block has no kernel version line"
    assert stated.group(1) == project["version"], (stated.group(1), project["version"])
    protocol = next(d for d in project["dependencies"] if d.startswith("actenon-protocol"))
    assert f"`{protocol}`" in block, (protocol, block)
    assert f"`{project['requires-python']}` (kernel alone)" in block
