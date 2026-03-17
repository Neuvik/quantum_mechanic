# ================================================================
# MODULE: quantum_mechanic.core.store.principals
# ----------------------------------------------------------------
# PURPOSE:   IAM principal CRUD operations for a workspace.
#            Extracted from workspace.py (RC-2) — Workspace
#            delegates every principal method here.
#
# AR-3: sqlite3 path only (local/public mode).
#       SQLAlchemy path deferred until the ORM migration lands.
# ================================================================

from __future__ import annotations

import logging

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.models import Principal

logger = logging.getLogger(__name__)


class PrincipalStore:
    """Principal CRUD operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

    def add(self, principal: Principal) -> None:
        """Add or update a principal."""
        self._db.execute(
            """
            INSERT OR REPLACE INTO principals
                (id, provider, account_id, principal_type, friendly_name,
                 is_admin_equivalent, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                principal.id, principal.provider, principal.account_id,
                principal.principal_type, principal.friendly_name,
                int(principal.is_admin_equivalent), principal.raw_data,
            ),
        )
        self._db.commit()

    def get(self, provider: str, principal_id: str) -> Principal | None:
        """Retrieve a principal by provider and ID."""
        row = self._db.fetchone(
            "SELECT * FROM principals WHERE provider = ? AND id = ?",
            (provider, principal_id),
        )
        if row is None:
            return None
        return Principal(
            id=row["id"], provider=row["provider"],
            account_id=row["account_id"], principal_type=row["principal_type"],
            friendly_name=row["friendly_name"],
            is_admin_equivalent=bool(row["is_admin_equivalent"]),
            raw_data=row["raw_data"],
        )

    def list(self, *, provider: str | None = None) -> list[Principal]:
        """List all principals, optionally filtered by provider."""
        if provider:
            rows = self._db.fetchall(
                "SELECT * FROM principals WHERE provider = ? ORDER BY friendly_name",
                (provider,),
            )
        else:
            rows = self._db.fetchall("SELECT * FROM principals ORDER BY friendly_name")
        return [
            Principal(
                id=r["id"], provider=r["provider"],
                account_id=r["account_id"], principal_type=r["principal_type"],
                friendly_name=r["friendly_name"],
                is_admin_equivalent=bool(r["is_admin_equivalent"]),
                raw_data=r["raw_data"],
            )
            for r in rows
        ]
