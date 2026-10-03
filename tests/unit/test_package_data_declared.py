"""Every non-Python file under actenon/ must ship in the wheel.

setuptools is configured with include-package-data = false, so a data file
ships only when [tool.setuptools.package-data] declares it. The scanner's
capability registry was never declared: `actenon-kernel scan` and
`actenon-kernel doctor --deep` failed with FileNotFoundError from every
installed wheel (released 1.2.1 included), while passing from a checkout.
"""

from __future__ import annotations

import fnmatch
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10: tomli is a dev dependency there
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]


def _declared() -> dict[str, list[str]]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return data["tool"]["setuptools"]["package-data"]


def _shipped(path: Path, declared: dict[str, list[str]]) -> bool:
    rel = path.relative_to(ROOT)
    for package, patterns in declared.items():
        package_dir = Path(*package.split("."))
        try:
            inner = rel.relative_to(package_dir)
        except ValueError:
            continue
        if any(fnmatch.fnmatch(inner.as_posix(), pattern) for pattern in patterns):
            return True
    return False


def test_every_data_file_under_actenon_is_declared_package_data():
    declared = _declared()
    missing = [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "actenon").rglob("*"))
        if path.is_file() and path.suffix not in {".py", ".pyc"} and "__pycache__" not in path.parts
        and not _shipped(path, declared)
    ]
    assert missing == [], f"not shipped in the wheel: {missing}"
