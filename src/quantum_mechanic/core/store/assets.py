# ================================================================
# MODULE: quantum_mechanic.core.store.assets
# ----------------------------------------------------------------
# PURPOSE:   Compute instance and network asset upsert/list for a
#            workspace. Extracted from workspace.py (RC-2).
# ================================================================

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)


class AssetStore:
    """Compute and network asset operations scoped to a single workspace."""

    def __init__(self, db: Database, workspace_id: str) -> None:
        self._db = db
        self._workspace_id = workspace_id

    def upsert_compute_instance(
        self,
        *,
        provider: str,
        instance_id: str,
        name: str | None = None,
        state: str | None = None,
        instance_type: str | None = None,
        private_ip: str | None = None,
        public_ip: str | None = None,
        subnet_id: str | None = None,
        image_id: str | None = None,
        identity_arn: str | None = None,
        identity_name: str | None = None,
        security_group_ids: str = "[]",
        metadata: str = "{}",
    ) -> None:
        """Insert or update a compute instance record.

        Uses ON CONFLICT … DO UPDATE so repeated enum_compute runs
        update in place rather than stacking duplicate rows.
        """
        now = datetime.now(UTC).isoformat()
        self._db.execute(
            """
            INSERT INTO compute_instances
                (workspace_id, provider, instance_id, name, state,
                 instance_type, private_ip, public_ip, subnet_id,
                 image_id, identity_arn, identity_name, security_group_ids,
                 metadata, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, provider, instance_id) DO UPDATE SET
                name            = excluded.name,
                state           = excluded.state,
                instance_type   = excluded.instance_type,
                private_ip      = excluded.private_ip,
                public_ip       = excluded.public_ip,
                subnet_id       = excluded.subnet_id,
                image_id        = excluded.image_id,
                identity_arn    = excluded.identity_arn,
                identity_name   = excluded.identity_name,
                security_group_ids = excluded.security_group_ids,
                metadata        = excluded.metadata,
                last_seen       = excluded.last_seen
            """,
            (
                self._workspace_id, provider, instance_id, name, state,
                instance_type, private_ip, public_ip, subnet_id,
                image_id, identity_arn, identity_name, security_group_ids,
                metadata, now, now,
            ),
        )
        self._db.commit()

    def upsert_network_asset(
        self,
        *,
        provider: str,
        asset_type: str,
        asset_id: str,
        name: str | None = None,
        region: str | None = None,
        metadata: str = "{}",
    ) -> None:
        """Insert or update a network asset (subnet, SG, VPC, etc.)."""
        now = datetime.now(UTC).isoformat()
        self._db.execute(
            """
            INSERT INTO network_assets
                (workspace_id, provider, asset_type, asset_id, name,
                 region, metadata, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, provider, asset_type, asset_id) DO UPDATE SET
                name      = excluded.name,
                region    = excluded.region,
                metadata  = excluded.metadata,
                last_seen = excluded.last_seen
            """,
            (
                self._workspace_id, provider, asset_type, asset_id, name,
                region, metadata, now, now,
            ),
        )
        self._db.commit()

    def list_compute_instances(self, *, provider: str | None = None) -> list[dict]:
        """Return all known compute instances, optionally filtered by provider."""
        sql = "SELECT * FROM compute_instances WHERE workspace_id = ?"
        params: list[Any] = [self._workspace_id]
        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        sql += " ORDER BY provider, instance_id"
        rows = self._db.fetchall(sql, tuple(params))
        return [dict(r) for r in rows]
