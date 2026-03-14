# ================================================================
# MODULE: quantum_mechanic.core.workspace
# ----------------------------------------------------------------
# PURPOSE:   High-level workspace operations. Wraps the database
#            layer with domain-specific methods for credentials,
#            principals, accounts, and API logging.
#
# DESIGN:    The workspace is the unit of organization. One
#            workspace per engagement. All data flows through
#            workspace methods to ensure consistency and logging.
# ================================================================

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from quantum_mechanic.core.database import Database

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """Represents a stored credential."""

    id: int
    provider: str
    credential_type: str
    friendly_name: str | None
    principal_id: str | None
    account_id: str | None
    derived_from_id: int | None
    expires_at: str | None
    auto_refresh: bool
    status: str
    obtained_via: str | None
    created_at: str
    raw_data: str | None = None
    # --------------------------------------------------------
    # secret_data is intentionally NOT stored in this dataclass.
    # It is only accessed through the credential manager to
    # enforce encryption boundaries.
    # --------------------------------------------------------


@dataclass
class Principal:
    """Represents a cloud identity."""

    id: str
    provider: str
    account_id: str | None
    principal_type: str
    friendly_name: str | None
    is_admin_equivalent: bool = False
    raw_data: str | None = None


@dataclass
class Agent:
    """Represents a Neutrino C2 agent."""

    id: str
    hostname: str | None
    username: str | None
    internal_ip: str | None
    platform: str | None
    arch: str | None
    os_version: str | None
    agent_version: str | None
    profile: str | None
    status: str
    latency_ms: int
    registered_at: str
    last_seen: str


@dataclass
class Task:
    """Represents a job queued for a Neutrino agent."""

    id: str
    agent_id: str
    command: str
    args: bytes | None
    status: str
    output: bytes | None
    error: str | None
    created_at: str
    completed_at: str | None


@dataclass
class Account:
    """Represents a cloud account/tenant/subscription/project."""

    id: str
    provider: str
    name: str | None
    account_type: str | None
    parent_id: str | None = None
    metadata: str | None = None


@dataclass
class ApiLogEntry:
    """Represents a single API call in the audit log."""

    id: int
    timestamp: str
    credential_id: int | None
    provider: str
    service: str | None
    action: str
    request_params: str | None
    response_status: int | None
    response_summary: str | None
    technique_id: str | None
    duration_ms: int | None


class Workspace:
    """High-level workspace operations.

    Wraps the database with domain-specific methods for managing
    credentials, principals, accounts, and API logs.
    """

    def __init__(self, db: Database, name: str) -> None:
        self.db = db
        self.name = name
        
        # Load the UUID id assigned during Database._init_workspace
        row = self.db.fetchone("SELECT id FROM workspace WHERE name = ?", (name,))
        self.id = row["id"] if row else name
        
        self._active_credential_id: int | None = None
        self._agent_callbacks: list = []

    def on_agent_update(self, cb: Callable[["Agent"], None]) -> None:
        """Register a callback for agent updates (used by SSE)."""
        self._agent_callbacks.append(cb)

    def _notify_agent(self, agent_id: str) -> None:
        """Trigger callbacks for a specific agent."""
        agent = self.get_agent(agent_id)
        if agent:
            for cb in self._agent_callbacks:
                try:
                    cb(agent)
                except Exception as e:
                    logger.debug("Agent update callback failed for %s: %s", agent_id, e)

    @classmethod
    def create(cls, name: str, workspace_dir: Path | None = None) -> Workspace:
        """Create a new workspace."""
        db = Database.create(name, workspace_dir)
        return cls(db, name)

    @classmethod
    def load(cls, name: str, workspace_dir: Path | None = None) -> Workspace:
        """Load an existing workspace."""
        db = Database.load(name, workspace_dir)
        return cls(db, name)

    @classmethod
    def list_all(cls, workspace_dir: Path | None = None) -> list[dict[str, Any]]:
        """List all available workspaces."""
        return Database.list_workspaces(workspace_dir)

    @property
    def active_credential_id(self) -> int | None:
        """ID of the currently active credential."""
        return self._active_credential_id

    @active_credential_id.setter
    def active_credential_id(self, cred_id: int | None) -> None:
        """Set the active credential by ID."""
        if cred_id is not None:
            row = self.db.fetchone("SELECT id FROM credentials WHERE id = ?", (cred_id,))
            if row is None:
                raise ValueError(f"Credential #{cred_id} not found")
        self._active_credential_id = cred_id

    # ================================================================
    # Agent operations
    # ================================================================

    def register_agent(self, agent: Agent) -> None:
        """Register or update a Neutrino agent."""
        self.db.execute(
            """
            INSERT INTO agents
                (id, workspace_id, hostname, username, internal_ip, platform, arch,
                 os_version, agent_version, profile, status, latency_ms,
                 registered_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname = excluded.hostname,
                username = excluded.username,
                internal_ip = excluded.internal_ip,
                platform = excluded.platform,
                arch = excluded.arch,
                os_version = excluded.os_version,
                agent_version = excluded.agent_version,
                profile = excluded.profile,
                status = excluded.status,
                latency_ms = excluded.latency_ms,
                last_seen = excluded.last_seen
            """,
            (
                agent.id,
                self.id,
                agent.hostname,
                agent.username,
                agent.internal_ip,
                agent.platform,
                agent.arch,
                agent.os_version,
                agent.agent_version,
                agent.profile,
                agent.status,
                agent.latency_ms,
                agent.registered_at,
                agent.last_seen,
            ),
        )
        self.db.commit()
        self._notify_agent(agent.id)

    def heartbeat_agent(self, agent_id: str, latency_ms: int) -> None:
        """Record an agent heartbeat."""
        now = datetime.now(UTC).isoformat()
        self.db.execute(
            "UPDATE agents SET last_seen = ?, latency_ms = ?, status = 'active' WHERE id = ?",
            (now, latency_ms, agent_id),
        )
        self.db.commit()
        self._notify_agent(agent_id)

    def deregister_agent(self, agent_id: str) -> None:
        """Mark an agent as inactive due to deregistration."""
        self.db.execute(
            "UPDATE agents SET status = 'inactive' WHERE id = ?",
            (agent_id,),
        )
        self.db.commit()
        self._notify_agent(agent_id)

    def revoke_agent(self, agent_id: str) -> None:
        """Revoke an agent (refuse future connections)."""
        self.db.execute(
            "UPDATE agents SET status = 'revoked' WHERE id = ?",
            (agent_id,),
        )
        self.db.commit()
        self._notify_agent(agent_id)

    # ================================================================
    # Task operations
    # ================================================================

    def queue_task(self, agent_id: str, command: str, args: bytes | None = None) -> str:
        """Queue a task for an agent."""
        import uuid
        task_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        
        self.db.execute(
            """
            INSERT INTO tasks (id, workspace_id, agent_id, command, args, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """,
            (task_id, self.id, agent_id, command, args, now)
        )
        self.db.commit()
        return task_id

    def pop_tasks(self, agent_id: str) -> list[Task]:
        """Fetch all pending tasks for an agent and mark them running."""
        now = datetime.now(UTC).isoformat()
        
        rows = self.db.fetchall(
            """
            SELECT id, agent_id, command, args, status, output, error, created_at, completed_at
            FROM tasks
            WHERE workspace_id = ? AND agent_id = ? AND status = 'pending'
            """,
            (self.id, agent_id)
        )
        
        tasks = []
        for r in rows:
            self.db.execute(
                "UPDATE tasks SET status = 'running' WHERE id = ?",
                (r["id"],)
            )
            tasks.append(
                Task(
                    id=r["id"],
                    agent_id=r["agent_id"],
                    command=r["command"],
                    args=r["args"],
                    status="running",
                    output=r["output"],
                    error=r["error"],
                    created_at=r["created_at"],
                    completed_at=r["completed_at"],
                )
            )
        
        if tasks:
            self.db.commit()
            
        return tasks

    def process_task_response(self, task_id: str, success: bool, output: bytes | None, error: str | None) -> None:
        """Update a task with its final result from the agent."""
        now = datetime.now(UTC).isoformat()
        status = "completed" if success else "failed"
        
        self.db.execute(
            """
            UPDATE tasks 
            SET status = ?, output = ?, error = ?, completed_at = ?
            WHERE id = ? AND workspace_id = ?
            """,
            (status, output, error, now, task_id, self.id)
        )
        self.db.commit()

    def get_agent(self, agent_id: str) -> Agent | None:
        """Retrieve an agent by ID."""
        row = self.db.fetchone("SELECT * FROM agents WHERE id = ?", (agent_id,))
        if row is None:
            return None
        return Agent(
            id=row["id"],
            hostname=row["hostname"],
            username=row["username"],
            internal_ip=row["internal_ip"],
            platform=row["platform"],
            arch=row["arch"],
            os_version=row["os_version"],
            agent_version=row["agent_version"],
            profile=row["profile"],
            status=row["status"],
            latency_ms=row["latency_ms"],
            registered_at=row["registered_at"],
            last_seen=row["last_seen"],
        )

    # ================================================================
    # Account operations
    # ================================================================

    def add_account(self, account: Account) -> None:
        """Add or update a cloud account."""
        self.db.execute(
            """
            INSERT OR REPLACE INTO accounts (id, provider, name, account_type, parent_id, metadata)
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
        self.db.commit()

    def get_account(self, account_id: str) -> Account | None:
        """Retrieve an account by ID."""
        row = self.db.fetchone("SELECT * FROM accounts WHERE id = ?", (account_id,))
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

    # ================================================================
    # Credential operations
    # ================================================================

    def add_credential(
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
        """Store a new credential in the workspace.

        Args:
            provider: Cloud provider (aws, azure, gcp, oci).
            credential_type: Type of credential.
            secret_data: Encrypted credential material.
            friendly_name: Human-readable identifier.
            principal_id: Who this authenticates as.
            account_id: Which account/tenant.
            derived_from_id: Parent credential (provenance).
            expires_at: ISO 8601 expiration timestamp.
            auto_refresh: Whether this can be auto-refreshed.
            obtained_via: How the credential was obtained.
            raw_data: Full API response JSON.

        Returns:
            The ID of the new credential.
        """
        cursor = self.db.execute(
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
        self.db.commit()
        # DB-1 AUDIT: cursor.lastrowid is safe here. Each Workspace holds a
        # single sqlite3.Connection (check_same_thread=False, WAL mode). The
        # technique runner is single-threaded per workspace; only one INSERT
        # can be in flight at a time, so lastrowid always refers to this row.
        return cursor.lastrowid  # type: ignore[return-value]

    def get_credential(self, cred_id: int) -> Credential | None:
        """Retrieve a credential by ID (without secret_data)."""
        row = self.db.fetchone("SELECT * FROM credentials WHERE id = ?", (cred_id,))
        if row is None:
            return None
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

    def get_credential_secret(self, cred_id: int) -> str | None:
        """Retrieve the encrypted secret_data for a credential.

        This is kept separate from get_credential() to enforce
        explicit access to sensitive material.
        """
        row = self.db.fetchone("SELECT secret_data FROM credentials WHERE id = ?", (cred_id,))
        if row is None:
            return None
        return row["secret_data"]

    def list_credentials(
        self, *, provider: str | None = None, status: str | None = None
    ) -> list[Credential]:
        """List credentials with optional filters."""
        # WHERE 1=1 is an intentional pattern that makes it trivially safe
        # to append AND clauses in the loop below without special-casing
        # whether it's the first predicate. This is idiomatic SQL
        # for optional filter chaining.
        sql = "SELECT * FROM credentials WHERE 1=1"
        params: list[Any] = []

        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        if status:
            sql += " AND status = ?"
            params.append(status)

        sql += " ORDER BY id"
        rows = self.db.fetchall(sql, tuple(params))
        return [
            Credential(
                id=r["id"],
                provider=r["provider"],
                credential_type=r["credential_type"],
                friendly_name=r["friendly_name"],
                principal_id=r["principal_id"],
                account_id=r["account_id"],
                derived_from_id=r["derived_from_id"],
                expires_at=r["expires_at"],
                auto_refresh=bool(r["auto_refresh"]),
                status=r["status"],
                obtained_via=r["obtained_via"],
                created_at=r["created_at"],
                raw_data=r["raw_data"],
            )
            for r in rows
        ]

    def update_credential_status(self, cred_id: int, status: str) -> None:
        """Update the status of a credential."""
        self.db.execute(
            "UPDATE credentials SET status = ? WHERE id = ?",
            (status, cred_id),
        )
        self.db.commit()

    def delete_credential(self, cred_id: int) -> bool:
        """Delete a credential by ID.

        Handles foreign key references gracefully:
          - api_log.credential_id → set to NULL (preserve audit trail)
          - credentials.derived_from_id → set to NULL (unlink children)

        Returns:
            True if deleted, False if not found.
        """
        row = self.db.fetchone("SELECT id FROM credentials WHERE id = ?", (cred_id,))
        if row is None:
            return False

        # --------------------------------------------------------
        # Null out FK references before deleting.
        # The audit trail (api_log) is NEVER deleted — we just
        # unlink it from the credential that no longer exists.
        # Child credentials lose their parent link but survive.
        # --------------------------------------------------------
        self.db.execute(
            "UPDATE api_log SET credential_id = NULL WHERE credential_id = ?",
            (cred_id,),
        )
        self.db.execute(
            "UPDATE credentials SET derived_from_id = NULL WHERE derived_from_id = ?",
            (cred_id,),
        )

        self.db.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        self.db.commit()

        if self._active_credential_id == cred_id:
            self._active_credential_id = None
        return True

    def update_credential_principal(
        self, cred_id: int, principal_id: str, friendly_name: str | None = None
    ) -> None:
        """Link a credential to a discovered principal."""
        sql = "UPDATE credentials SET principal_id = ?"
        params: list[Any] = [principal_id]
        if friendly_name:
            sql += ", friendly_name = ?"
            params.append(friendly_name)
        sql += " WHERE id = ?"
        params.append(cred_id)
        self.db.execute(sql, tuple(params))
        self.db.commit()

    # ================================================================
    # Principal operations
    # ================================================================

    def add_principal(self, principal: Principal) -> None:
        """Add or update a principal."""
        self.db.execute(
            """
            INSERT OR REPLACE INTO principals
                (id, provider, account_id, principal_type, friendly_name,
                 is_admin_equivalent, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                principal.id,
                principal.provider,
                principal.account_id,
                principal.principal_type,
                principal.friendly_name,
                int(principal.is_admin_equivalent),
                principal.raw_data,
            ),
        )
        self.db.commit()

    def get_principal(self, provider: str, principal_id: str) -> Principal | None:
        """Retrieve a principal by provider and ID."""
        row = self.db.fetchone(
            "SELECT * FROM principals WHERE provider = ? AND id = ?",
            (provider, principal_id),
        )
        if row is None:
            return None
        return Principal(
            id=row["id"],
            provider=row["provider"],
            account_id=row["account_id"],
            principal_type=row["principal_type"],
            friendly_name=row["friendly_name"],
            is_admin_equivalent=bool(row["is_admin_equivalent"]),
            raw_data=row["raw_data"],
        )

    # ================================================================
    # API log operations
    # ================================================================

    def log_api_call(
        self,
        provider: str,
        action: str,
        credential_id: int | None = None,
        service: str | None = None,
        request_params: str | None = None,
        response_status: int | None = None,
        response_summary: str | None = None,
        technique_id: str | None = None,
        duration_ms: int | None = None,
    ) -> int:
        """Append an API call to the audit log.

        Returns:
            The ID of the new log entry.
        """
        now = datetime.now(UTC).isoformat()
        cursor = self.db.execute(
            """
            INSERT INTO api_log
                (timestamp, credential_id, provider, service, action,
                 request_params, response_status, response_summary,
                 technique_id, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                credential_id,
                provider,
                service,
                action,
                request_params,
                response_status,
                response_summary,
                technique_id,
                duration_ms,
            ),
        )
        self.db.commit()
        # DB-1 AUDIT: see add_credential — single-connection, single-threaded.
        return cursor.lastrowid  # type: ignore[return-value]

    def save_evidence(
        self,
        technique_id: str,
        output_json: str,
        credential_id: int | None = None,
    ) -> int:
        """Save the raw JSON output of a technique to the evidence table.

        Args:
            technique_id: The ID of the technique executed.
            output_json: The raw JSON output payload.
            credential_id: Optional ID of the credential used.

        Returns:
            The ID of the new evidence entry.
        """
        now = datetime.now(UTC).isoformat()
        cursor = self.db.execute(
            """
            INSERT INTO evidence
                (workspace_id, technique_id, credential_id, timestamp, output_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                self.id,
                technique_id,
                credential_id,
                now,
                output_json,
            ),
        )
        self.db.commit()
        # DB-1 AUDIT: see add_credential — single-connection, single-threaded.
        return cursor.lastrowid  # type: ignore[return-value]

    def list_evidence(self) -> list[dict]:
        """Return all evidence rows, ordered by timestamp ascending.

        Used by attack_path.py to build the technique timeline.

        Returns:
            List of dicts with keys: id, timestamp, technique_id,
            credential_id, output_json.
        """
        rows = self.db.fetchall(
            """
            SELECT id, timestamp, technique_id, credential_id, output_json
            FROM evidence
            WHERE workspace_id = ?
            ORDER BY timestamp ASC
            """,
            (self.id,),
        )
        return [dict(r) for r in rows]

    def list_findings(self) -> list[dict]:
        """Return all findings, ordered by severity then timestamp.

        Used by attack_path.py to build the findings summary.

        Returns:
            List of dicts with all findings columns.
        """
        rows = self.db.fetchall(
            """
            SELECT id, technique_id, tactic, mitre_id, title, severity,
                   provider, description, evidence, created_at
            FROM findings
            WHERE workspace_id = ?
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high'     THEN 2
                    WHEN 'medium'   THEN 3
                    WHEN 'low'      THEN 4
                    ELSE 5
                END,
                created_at ASC
            """,
            (self.id,),
        )
        return [dict(r) for r in rows]

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

        Uses INSERT OR REPLACE so repeated enum_compute runs update
        in place rather than stacking duplicate rows.
        """
        now = datetime.now(UTC).isoformat()
        self.db.execute(
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
                self.id, provider, instance_id, name, state,
                instance_type, private_ip, public_ip, subnet_id,
                image_id, identity_arn, identity_name, security_group_ids,
                metadata, now, now,
            ),
        )
        self.db.commit()

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
        """Insert or update a network asset (subnet, security group, VPC, etc.)."""
        now = datetime.now(UTC).isoformat()
        self.db.execute(
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
                self.id, provider, asset_type, asset_id, name,
                region, metadata, now, now,
            ),
        )
        self.db.commit()

    def list_compute_instances(self, *, provider: str | None = None) -> list[dict]:
        """Return all known compute instances, optionally filtered by provider."""
        sql = "SELECT * FROM compute_instances WHERE workspace_id = ?"
        params: list[Any] = [self.id]
        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        sql += " ORDER BY provider, instance_id"
        rows = self.db.fetchall(sql, tuple(params))
        return [dict(r) for r in rows]

    def add_finding(

        self,
        *,
        technique_id: str,
        tactic: str,
        title: str,
        severity: str,
        provider: str,
        description: str,
        evidence: str,
        mitre_id: str | None = None,
    ) -> int:
        """Persist a security finding derived from technique output.

        Called by the runner for each risk_flag the summarizer detects.
        Feeds list_findings() -> attack_path.py -> ATTACK_PATH.md.

        Returns:
            The ID of the new finding row.
        """
        cursor = self.db.execute(
            """
            INSERT OR IGNORE INTO findings
                (workspace_id, technique_id, tactic, mitre_id, title,
                 severity, provider, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.id,
                technique_id,
                tactic,
                mitre_id,
                title,
                severity,
                provider,
                description,
                evidence,
            ),
        )
        self.db.commit()
        # DB-1 AUDIT: INSERT OR IGNORE — lastrowid is 0 when the row is
        # silently ignored (duplicate). Callers that need the ID of an
        # existing duplicate must re-query by (technique_id, title).
        return cursor.lastrowid  # type: ignore[return-value]

    def close(self) -> None:
        """Close the workspace database connection."""
        self.db.close()
