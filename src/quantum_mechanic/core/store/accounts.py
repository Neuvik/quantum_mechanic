# ================================================================
# MODULE: quantum_mechanic.core.store.accounts
# ----------------------------------------------------------------
# PURPOSE:   Cloud account CRUD operations for a workspace.
#            Extracted from workspace.py (RC-2) — Workspace
#            delegates every account method here.
#
# AR-3: sqlite3 path only (local/public mode).
#       SQLAlchemy path deferred until the ORM migration lands.
# ================================================================

from __future__ import annotations

import logging

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.models import Account

logger = logging.getLogger(__name__)


class AccountStore:
    """Account CRUD operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

    def add(self, account: Account) -> None:
        """Add or update a cloud account."""
        self._db.execute(
            """
            INSERT OR REPLACE INTO accounts
                (id, provider, name, account_type, parent_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                account.id,
                account.provider,
                account.name,
                account.account_type,
                account.parent_id,
                account.metadata,
            ),
        )
        self._db.commit()

    def get(self, account_id: str) -> Account | None:
        """Retrieve an account by ID."""
        row = self._db.fetchone("SELECT * FROM accounts WHERE id = ?", (account_id,))
        if row is None:
            return None
        return Account(
            id=row["id"],
            provider=row["provider"],
            name=row["name"],
            account_type=row["account_type"],
            parent_id=row["parent_id"],
            metadata=row["metadata"],
        )

    def list(self, *, provider: str | None = None) -> list[Account]:
        """List all accounts, optionally filtered by provider."""
        if provider:
            rows = self._db.fetchall(
                "SELECT * FROM accounts WHERE provider = ? ORDER BY name",
                (provider,),
            )
        else:
            rows = self._db.fetchall("SELECT * FROM accounts ORDER BY name")
        return [
            Account(
                id=r["id"],
                provider=r["provider"],
                name=r["name"],
                account_type=r["account_type"],
                parent_id=r["parent_id"],
                metadata=r["metadata"],
            )
            for r in rows
        ]

    def close(self) -> None:
        """No-op for consistency."""
        pass
