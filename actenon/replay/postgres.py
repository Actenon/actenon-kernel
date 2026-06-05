from __future__ import annotations

from typing import Any, Callable

from .dbapi import DbApiReplayStore


class PostgresReplayStore(DbApiReplayStore):
    """PostgreSQL replay store for multi-instance protected endpoints.

    The adapter keeps the public ``ReplayStore`` contract unchanged and relies
    on PostgreSQL transactions plus the ``replay_key`` primary key to make
    duplicate claims fail atomically across workers.
    """

    parameter_placeholder = "%s"

    def __init__(
        self,
        dsn: str | None = None,
        *,
        connection_factory: Callable[[], Any] | None = None,
        connect_kwargs: dict[str, Any] | None = None,
    ) -> None:
        if connection_factory is None:
            if dsn is None:
                raise ValueError("PostgresReplayStore requires either dsn or connection_factory")
            connection_factory = self._connection_factory_from_dsn(dsn, connect_kwargs or {})
        super().__init__(connection_factory)

    def _connect(self):
        connection = super()._connect()
        if hasattr(connection, "autocommit"):
            connection.autocommit = False
        return connection

    @staticmethod
    def _connection_factory_from_dsn(dsn: str, connect_kwargs: dict[str, Any]) -> Callable[[], Any]:
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError:
            psycopg = None

        if psycopg is not None:
            return lambda: psycopg.connect(dsn, **connect_kwargs)

        try:
            import psycopg2  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ImportError(
                "PostgresReplayStore requires an optional PostgreSQL DB-API driver. "
                "Install `psycopg[binary]` or provide a compatible connection_factory."
            ) from exc

        return lambda: psycopg2.connect(dsn, **connect_kwargs)
