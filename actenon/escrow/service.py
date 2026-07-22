from __future__ import annotations

from pathlib import Path

from .base import CapabilityEscrow
from .sqlite import SqliteCapabilityEscrow


def default_escrow_db_path(base_dir: str | Path | None = None) -> Path:
    root = Path(base_dir) if base_dir is not None else Path.cwd() / ".actenon"
    return root / "escrow.sqlite3"


def build_default_capability_escrow(base_dir: str | Path | None = None) -> CapabilityEscrow:
    return SqliteCapabilityEscrow(default_escrow_db_path(base_dir))


def build_sqlite_capability_escrow(
    database_path: str | Path | None = None,
    *,
    base_dir: str | Path | None = None,
    timeout_seconds: float = 30.0,
) -> SqliteCapabilityEscrow:
    target = Path(database_path) if database_path is not None else default_escrow_db_path(base_dir)
    return SqliteCapabilityEscrow(target, timeout_seconds=timeout_seconds)
