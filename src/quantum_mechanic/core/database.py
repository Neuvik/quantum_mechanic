# ================================================================
# MODULE: quantum_mechanic.core.database
# ----------------------------------------------------------------
# PURPOSE:   SQLite wrapper for the workspace database. Handles
#            connection management, schema migrations, and
#            parameterized query helpers.
#
# DESIGN:    One SQLite file per engagement. Portable, no server,
#            works offline. Migrations are versioned SQL files
#            applied in order.
#
# USAGE:     db = Database.create("acme-test")
#            db = Database.load("acme-test")
#            db.execute("SELECT ...", params)
# ================================================================

from __future__ import annotations

import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ----------------------------------------------------------------
# Default workspace storage directory. Each workspace gets its
# own .db file under this directory.
#
# Override with QM_WORKSPACE_DIR to redirect workspaces (e.g.
# for isolated E2E tests).  Evaluated at call-time so that
# os.environ changes made before subprocess.spawn take effect.
# ----------------------------------------------------------------


def _default_workspace_dir() -> Path:
    """Return the workspace directory, respecting QM_WORKSPACE_DIR."""
    env = os.environ.get("QM_WORKSPACE_DIR")
    if env:
        return Path(env)
    return Path.home() / ".quantum_mechanic" / "workspaces"


# Module-level alias kept for backwards-compat — do NOT use inside
# create() / load(); call _default_workspace_dir() there instead.
DEFAULT_WORKSPACE_DIR = _default_workspace_dir()


class Database:
    """SQLite database wrapper for a QM workspace.

    Each workspace is a single SQLite file. The database handles
    schema migrations automatically on creation and load.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        # --------------------------------------------------------
        # check_same_thread=False allows sharing across FastAPI threads.
        # timeout=30.0 gives enough headroom for concurrent writes in WAL mode.
        # --------------------------------------------------------
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30.0)
        self._lock = threading.Lock()

        # --------------------------------------------------------
        # Enable WAL mode for better concurrent read performance
        # and return rows as sqlite3.Row for dict-like access.
        # --------------------------------------------------------
        with self._lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.row_factory = sqlite3.Row

    @classmethod
    def create(cls, name: str, workspace_dir: Path | None = None) -> Database:
        """Create a new workspace database.

        Args:
            name: Human-readable workspace name.
            workspace_dir: Override default storage directory.
                           Falls back to QM_WORKSPACE_DIR env var, then
                           ~/.quantum_mechanic/workspaces.

        Returns:
            Database instance with schema applied.

        Raises:
            FileExistsError: If workspace already exists.
        """
        base_dir = workspace_dir or _default_workspace_dir()
        base_dir.mkdir(parents=True, exist_ok=True)
        db_path = base_dir / f"{name}.db"

        if db_path.exists():
            raise FileExistsError(f"Workspace '{name}' already exists at {db_path}")

        db = cls(db_path)
        db._apply_migrations()
        db._init_workspace(name)
        return db

    @classmethod
    def load(cls, name: str, workspace_dir: Path | None = None) -> Database:
        """Load an existing workspace database.

        Args:
            name: Workspace name to load.
            workspace_dir: Override default storage directory.
                           Falls back to QM_WORKSPACE_DIR env var, then
                           ~/.quantum_mechanic/workspaces.

        Returns:
            Database instance.

        Raises:
            FileNotFoundError: If workspace does not exist.
        """
        base_dir = workspace_dir or _default_workspace_dir()
        db_path = base_dir / f"{name}.db"

        if not db_path.exists():
            raise FileNotFoundError(f"Workspace '{name}' not found at {db_path}")

        db = cls(db_path)
        db._apply_migrations()
        db._ensure_workspace(name)
        return db

    @classmethod
    def list_workspaces(cls, workspace_dir: Path | None = None) -> list[dict[str, Any]]:
        """List all available workspaces.

        Returns:
            List of dicts with name, path, and last modified time.
        """
        base_dir = workspace_dir or DEFAULT_WORKSPACE_DIR
        if not base_dir.exists():
            return []

        workspaces = []
        for db_file in sorted(base_dir.glob("*.db")):
            workspaces.append(
                {
                    "name": db_file.stem,
                    "path": str(db_file),
                    "modified": datetime.fromtimestamp(db_file.stat().st_mtime, tz=UTC).isoformat(),
                }
            )
        return workspaces

    @classmethod
    def delete(cls, name: str, workspace_dir: Path | None = None) -> None:
        """Delete a workspace: removes the .db file and the sibling `<name>/`
        directory that holds loot, exports, and other artifacts.

        Raises FileNotFoundError if the workspace .db doesn't exist.
        """
        import shutil

        base_dir = workspace_dir or _default_workspace_dir()
        db_path = base_dir / f"{name}.db"
        if not db_path.exists():
            raise FileNotFoundError(f"Workspace '{name}' not found at {db_path}")

        db_path.unlink()
        # Remove sibling artifact dir: workspaces/<name>/ (loot, bloodhound.json,
        # exports). The BloodHound export + loot writer both land here per the
        # `<db_path.parent>/<db_path.stem>/` convention (core/loot.py:155).
        artifact_dir = base_dir / name
        if artifact_dir.exists() and artifact_dir.is_dir():
            shutil.rmtree(artifact_dir)

    def execute(self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()) -> sqlite3.Cursor:
        """Execute a parameterized SQL statement.

        Args:
            sql: SQL statement with ? or :name placeholders.
            params: Parameters to bind.

        Returns:
            Cursor with results.
        """
        with self._lock:
            return self.conn.execute(sql, params)

    def execute_many(self, sql: str, params_list: list[tuple[Any, ...]]) -> None:
        """Execute a statement with multiple parameter sets."""
        with self._lock:
            self.conn.executemany(sql, params_list)

    def fetchone(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> sqlite3.Row | None:
        """Execute and fetch a single row."""
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    def fetchall(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> list[sqlite3.Row]:
        """Execute and fetch all rows."""
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def commit(self) -> None:
        """Commit the current transaction."""
        with self._lock:
            self.conn.commit()

    def close(self) -> None:
        """Close the database connection.

        AR-1: Idempotent — safe to call multiple times.
        """
        with self._lock:
            if self.conn is None:
                return
            self.conn.close()
            self.conn = None  # type: ignore[assignment]

    def _apply_migrations(self) -> None:
        """Apply any pending schema migrations.

        Migrations are SQL files in the migrations/ directory,
        named with a numeric prefix (001_, 002_, etc.) and applied
        in order. Each migration is idempotent and tracked in the
        _migrations table.
        """
        # --------------------------------------------------------
        # Create the migrations tracking table if it doesn't exist.
        # --------------------------------------------------------
        with self._lock:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS _migrations (
                    id INTEGER PRIMARY KEY,
                    filename TEXT NOT NULL UNIQUE,
                    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.conn.commit()

        migrations_dir = Path(__file__).parent / "migrations"
        if not migrations_dir.exists():
            return

        applied = {row["filename"] for row in self.fetchall("SELECT filename FROM _migrations")}

        for migration_file in sorted(migrations_dir.glob("*.sql")):
            if migration_file.name not in applied:
                sql = migration_file.read_text()
                with self._lock:
                    self.conn.executescript(sql)
                    self.conn.execute(
                        "INSERT INTO _migrations (filename) VALUES (?)",
                        (migration_file.name,),
                    )
                    self.conn.commit()

    def _init_workspace(self, name: str) -> None:
        """Initialize the workspace metadata row."""
        workspace_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        self.execute(
            """
            INSERT INTO workspace (id, name, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (workspace_id, name, now, now),
        )
        self.commit()

    def _ensure_workspace(self, name: str) -> None:
        """Ensure the workspace metadata row exists, creating it if missing."""
        row = self.fetchone("SELECT id FROM workspace WHERE name = ?", (name,))
        if not row:
            self._init_workspace(name)
        elif row["id"] == name:
            # Migration: if ID was incorrectly set to name, generate a new UUID.
            new_id = str(uuid.uuid4())
            self.execute("UPDATE workspace SET id = ? WHERE name = ?", (new_id, name))
            self.commit()
