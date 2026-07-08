"""Regression test: concurrent local SQLite replay-store use must not hit
'database is locked' when busy_timeout and WAL mode are configured.

This test exists because running quickstart_min.py and
interactive_execution_demo.py simultaneously against the default SQLite
replay DB caused sqlite3.OperationalError: database is locked.
"""

from __future__ import annotations

import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from actenon.replay.sqlite import SqliteReplayStore


@pytest.fixture
def temp_replay_db(tmp_path: Path) -> Path:
    return tmp_path / "concurrent_replay.sqlite3"


def test_concurrent_replay_store_initialization(temp_replay_db: Path) -> None:
    """Multiple threads initializing the replay store against the same DB
    file must not raise OperationalError."""
    errors: list[Exception] = []

    def init_store():
        try:
            store = SqliteReplayStore(temp_replay_db)
            # Touch the DB to force initialization
            store._create_connection().close()
        except Exception as exc:
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(lambda _: init_store(), range(20)))

    assert not errors, f"concurrent initialization failed: {errors}"


def test_concurrent_replay_store_reads(temp_replay_db: Path) -> None:
    """Multiple threads reading from the replay store simultaneously
    must not raise OperationalError."""
    store = SqliteReplayStore(temp_replay_db)
    errors: list[Exception] = []

    def read_store():
        try:
            conn = store._create_connection()
            try:
                conn.execute("SELECT COUNT(*) FROM action_consumption").fetchone()
            finally:
                conn.close()
        except Exception as exc:
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(lambda _: read_store(), range(50)))

    assert not errors, f"concurrent reads failed: {errors}"


def test_busy_timeout_is_set(temp_replay_db: Path) -> None:
    """The connection must have busy_timeout PRAGMA set."""
    store = SqliteReplayStore(temp_replay_db, timeout_seconds=15.0)
    conn = store._create_connection()
    try:
        result = conn.execute("PRAGMA busy_timeout").fetchone()
        assert result[0] == 15000, f"expected busy_timeout=15000, got {result[0]}"
    finally:
        conn.close()
