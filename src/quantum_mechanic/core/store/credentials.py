# ================================================================
# MODULE: quantum_mechanic.core.store.credentials
# ----------------------------------------------------------------
# PURPOSE:   All credential CRUD operations for a workspace.
#            Extracted from workspace.py (RC-2) — Workspace
#            delegates every credential method here.
#
# DESIGN:    CredentialStore holds a reference to the Database and
#            the workspace UUID. It never knows about the shell,
#            runner, or any other domain — pure data access.
# ================================================================

from __future__ import annotations

import logging
from typing import Any

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.models import Credential

logger = logging.getLogger(__name__)


class CredentialStore:
    """Credential CRUD operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

    # ================================================================
    # Write operations
    # ================================================================

    def add(
        self,
        provider: str,
        credential_type: str,
        secret_data: str,
        friendly_name: str | None = None,
        principal_id: str | None = None,
        account_id: str | None = None,
        derived_from_id: int | None = None,
        expires_at: str | None = None,
        auto_refresh: bool = False,
        obtained_via: str | None = None,
        raw_data: str | None = None,
    ) -> int:
        """Insert a new credential row.

        Returns:
            The ID of the new credential (cursor.lastrowid).

        DB-1 AUDIT: cursor.lastrowid is safe here. Each Workspace holds
        a single sqlite3.Connection (check_same_thread=False, WAL mode).
        The technique runner is single-threaded per workspace; only one
        INSERT can be in flight at a time, so lastrowid always refers to
        this row.
        """
        cursor = self._db.execute(
            """
            INSERT INTO credentials
                (provider, credential_type, friendly_name, principal_id,
                 account_id, derived_from_id, secret_data, expires_at,
                 auto_refresh, obtained_via, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                provider,
                credential_type,
                friendly_name,
                principal_id,
                account_id,
                derived_from_id,
                secret_data,
                expires_at,
                int(auto_refresh),
                obtained_via,
                raw_data,
            ),
        )
        self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def update_status(self, cred_id: int, status: str) -> None:
        """Update the lifecycle status of a credential."""
        self._db.execute(
            "UPDATE credentials SET status = ? WHERE id = ?",
            (status, cred_id),
        )
        self._db.commit()

    def update_principal(
        self, cred_id: int, principal_id: str, friendly_name: str | None = None
    ) -> None:
        """Link a credential to a discovered principal identity."""
        sql = "UPDATE credentials SET principal_id = ?"
        params: list[Any] = [principal_id]
        if friendly_name:
            sql += ", friendly_name = ?"
            params.append(friendly_name)
        sql += " WHERE id = ?"
        params.append(cred_id)
        self._db.execute(sql, tuple(params))
        self._db.commit()

    def delete(self, cred_id: int) -> bool:
        """Delete a credential by ID.

        Handles foreign key references gracefully:
          - api_log.credential_id → set to NULL (preserve audit trail)
          - credentials.derived_from_id → set to NULL (unlink children)

        Returns:
            True if deleted, False if not found.
        """
        row = self._db.fetchone("SELECT id FROM credentials WHERE id = ?", (cred_id,))
        if row is None:
            return False

        # --------------------------------------------------------
        # Null out FK references before deleting.
        # The audit trail (api_log) is NEVER deleted — we just
        # unlink it from the credential that no longer exists.
        # Child credentials lose their parent link but survive.
        # --------------------------------------------------------
        self._db.execute(
            "UPDATE api_log SET credential_id = NULL WHERE credential_id = ?",
            (cred_id,),
        )
        self._db.execute(
            "UPDATE credentials SET derived_from_id = NULL WHERE derived_from_id = ?",
            (cred_id,),
        )
        self._db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        self._db.commit()
        return True

    # ================================================================
    # Read operations
    # ================================================================

    def get(self, cred_id: int) -> Credential | None:
        """Retrieve a credential by ID (without secret_data)."""
        row = self._db.fetchone("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        if row is None:
            return None
        return self._row_to_credential(row)

    def get_secret(self, cred_id: int) -> str | None:
        """Retrieve the encrypted secret_data for a credential.

        Kept separate from get() to enforce explicit access to
        sensitive material.
        """
        row = self._db.fetchone(
            "SELECT secret_data FROM credentials WHERE id = ?", (cred_id,)
        )
        if row is None:
            return None
        return row["secret_data"]

    def list(
        self, *, provider: str | None = None, status: str | None = None
    ) -> list[Credential]:
        """List credentials with optional filters.

        Uses WHERE 1=1 to allow safe dynamic filter chaining.
        """
        sql = "SELECT * FROM credentials WHERE 1=1"
        params: list[Any] = []

        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        if status:
            sql += " AND status = ?"
            params.append(status)

        sql += " ORDER BY id"
        rows = self._db.fetchall(sql, tuple(params))
        return [self._row_to_credential(r) for r in rows]

    # ================================================================
    # Internal helpers
    # ================================================================

    def _row_to_credential(self, row) -> Credential:
        return Credential(
            id=row["id"],
            provider=row["provider"],
            credential_type=row["credential_type"],
            friendly_name=row["friendly_name"],
            principal_id=row["principal_id"],
            account_id=row["account_id"],
            derived_from_id=row["derived_from_id"],
            expires_at=row["expires_at"],
            auto_refresh=bool(row["auto_refresh"]),
            status=row["status"],
            obtained_via=row["obtained_via"],
            created_at=row["created_at"],
            raw_data=row["raw_data"],
        )
