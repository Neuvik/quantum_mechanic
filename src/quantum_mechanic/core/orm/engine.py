# ================================================================
# MODULE: quantum_mechanic.core.orm.engine
# ----------------------------------------------------------------
# PURPOSE:   Creates a SQLAlchemy Engine that points at either:
#            - SQLite (default, local/public mode)
#            - PostgreSQL (production qmd, via QM_DATABASE_URL)
#
# USAGE:
#   from quantum_mechanic.core.orm.engine import get_engine
#   engine = get_engine(sqlite_path=db.db_path)
#
# CONFIG:
#   QM_DATABASE_URL — override the SQLite default with any
#   SQLAlchemy-compatible URL, e.g.:
#     postgresql+psycopg2://user:pass@localhost/qmd
#
# NOTE: psycopg2-binary must be installed separately for the
#       PostgreSQL path: uv pip install 'quantum-mechanic[postgres]'
# ================================================================

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import Engine, create_engine, event


def get_engine(sqlite_path: Path | None = None) -> Engine:
    """Return a SQLAlchemy Engine for the active database backend.

    Priority:
        1. ``QM_DATABASE_URL`` env var (any SA-compatible URL)
        2. SQLite at ``sqlite_path`` (default for local mode)

    Args:
        sqlite_path: Path to the SQLite .db file. Ignored when
                     ``QM_DATABASE_URL`` is set.

    Returns:
        A configured SQLAlchemy ``Engine``.

    Raises:
        ValueError: If neither ``QM_DATABASE_URL`` nor ``sqlite_path``
                    is provided.
    """
    url = os.environ.get("QM_DATABASE_URL")

    if url:
        return create_engine(url, pool_pre_ping=True)

    if sqlite_path is None:
        raise ValueError(
            "Either QM_DATABASE_URL or sqlite_path must be provided."
        )

    engine = create_engine(
        f"sqlite:///{sqlite_path}",
        connect_args={"check_same_thread": False},
    )

    # ----------------------------------------------------------------
    # Mirror the Database class pragmas — WAL mode and FK enforcement
    # must be re-applied per-connection for SQLite (they don't persist
    # across connections in a pool).
    # ----------------------------------------------------------------
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine
