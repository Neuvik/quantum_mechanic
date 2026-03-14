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

import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ----------------------------------------------------------------
# Default workspace storage directory. Each workspace gets its
# own .db file under this directory.
# ----------------------------------------------------------------
DEFAULT_WORKSPACE_DIR = Path.home() / ".quantum_mechanic" / "workspaces"


class Database:
    """SQLite database wrapper for a QM workspace.

    Each workspace is a single SQLite file. The database handles
    schema migrations automatically on creation and load.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        # --------------------------------------------------------
        # Enable WAL mode for better concurrent read performance
        # and return rows as sqlite3.Row for dict-like access.
        # --------------------------------------------------------
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.row_factory = sqlite3.Row

    @classmethod
    def create(cls, name: str, workspace_dir: Path | None = None) -> Database:
        """Create a new workspace database.

        Args:
            name: Human-readable workspace name.
            workspace_dir: Override default storage directory.

        Returns:
            Database instance with schema applied.

        Raises:
            FileExistsError: If workspace already exists.
        """
        base_dir = workspace_dir or DEFAULT_WORKSPACE_DIR
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

        Returns:
            Database instance.

        Raises:
            FileNotFoundError: If workspace does not exist.
        """
        base_dir = workspace_dir or DEFAULT_WORKSPACE_DIR
        db_path = base_dir / f"{name}.db"

        if not db_path.exists():
            raise FileNotFoundError(f"Workspace '{name}' not found at {db_path}")

        db = cls(db_path)
        db._apply_migrations()
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

    def execute(self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()) -> sqlite3.Cursor:
        """Execute a parameterized SQL statement.

        Args:
            sql: SQL statement with ? or :name placeholders.
            params: Parameters to bind.

        Returns:
            Cursor with results.
        """
        return self.conn.execute(sql, params)

    def execute_many(self, sql: str, params_list: list[tuple[Any, ...]]) -> None:
        """Execute a statement with multiple parameter sets."""
        self.conn.executemany(sql, params_list)

    def fetchone(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> sqlite3.Row | None:
        """Execute and fetch a single row."""
        return self.conn.execute(sql, params).fetchone()

    def fetchall(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> list[sqlite3.Row]:
        """Execute and fetch all rows."""
        return self.conn.execute(sql, params).fetchall()

    def commit(self) -> None:
        """Commit the current transaction."""
        self.conn.commit()

    def close(self) -> None:
        """Close the database connection.

        AR-1: Idempotent — safe to call multiple times. If Close() is
        called on an already-closed database it is a no-op. This is
        important because the shell holds a long-lived workspace
        reference and close() may be triggered both by 'workspace load'
        (switching engagement) and by shell exit.
        """
        if self.conn is None:
            return
        self.conn.close()
        self.conn = None  # type: ignore[assignment]  # sentinel for idempotency

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
                self.conn.executescript(sql)
                self.execute(
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
