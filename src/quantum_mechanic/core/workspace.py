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
from pathlib import Path
from typing import Any

from quantum_mechanic.core.database import Database
from quantum_mechanic.core.store.accounts import AccountStore
from quantum_mechanic.core.store.agents import AgentStore
from quantum_mechanic.core.store.assets import AssetStore
from quantum_mechanic.core.store.credentials import CredentialStore
from quantum_mechanic.core.store.evidence import EvidenceStore
from quantum_mechanic.core.store.findings import FindingStore
from quantum_mechanic.core.store.principals import PrincipalStore

logger = logging.getLogger(__name__)


from quantum_mechanic.core.store.models import (  # noqa: F401 — re-exported for callers
    Account,
    Agent,
    ApiLogEntry,
    Credential,
    Principal,
    Task,
)


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

        # --------------------------------------------------------
        # Domain stores — each owns one slice of the schema.
        # Workspace delegates every domain method here, keeping
        # the ORM migration (AR-3) domain-by-domain.
        # --------------------------------------------------------
        self._accounts    = AccountStore(db, self.id)
        self._agents      = AgentStore(db, self.id)
        self._assets      = AssetStore(db, self.id)
        self._credentials = CredentialStore(db, self.id)
        self._evidence    = EvidenceStore(db, self.id)
        self._findings    = FindingStore(db, self.id)
        self._principals  = PrincipalStore(db, self.id)

    def on_agent_update(self, cb) -> None:
        """Register a callback for agent updates (used by SSE)."""
        self._agents.on_update(cb)


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
    # Agent operations — delegates to AgentStore
    # ================================================================

    def register_agent(self, agent: Agent) -> None:
        """Register or update a Neutrino agent."""
        return self._agents.register(agent)

    def heartbeat_agent(self, agent_id: str, latency_ms: int) -> None:
        """Record an agent heartbeat."""
        return self._agents.heartbeat(agent_id, latency_ms)

    def deregister_agent(self, agent_id: str) -> None:
        """Mark an agent as inactive due to deregistration."""
        return self._agents.deregister(agent_id)

    def revoke_agent(self, agent_id: str) -> None:
        """Revoke an agent (refuse future connections)."""
        return self._agents.revoke(agent_id)

    def get_agent(self, agent_id: str) -> Agent | None:
        """Retrieve an agent by ID."""
        return self._agents.get(agent_id)

    # ================================================================
    # Task operations — delegates to AgentStore
    # ================================================================

    def queue_task(self, agent_id: str, command: str, args: bytes | None = None) -> str:
        """Queue a task for an agent."""
        return self._agents.queue_task(agent_id, command, args)

    def pop_tasks(self, agent_id: str) -> list[Task]:
        """Fetch all pending tasks and mark them running."""
        return self._agents.pop_tasks(agent_id)

    def process_task_response(
        self, task_id: str, success: bool, output: bytes | None, error: str | None
    ) -> None:
        """Update a task with its final result from the agent."""
        return self._agents.process_task_response(task_id, success, output, error)


    # ================================================================
    # Account operations — delegates to AccountStore
    # ================================================================

    def add_account(self, account: Account) -> None:
        """Add or update a cloud account."""
        return self._accounts.add(account)

    def get_account(self, account_id: str) -> Account | None:
        """Retrieve an account by ID."""
        return self._accounts.get(account_id)

    # ================================================================
    # Principal operations — delegates to PrincipalStore
    # ================================================================

    def add_principal(self, principal: Principal) -> None:
        """Add or update a principal."""
        return self._principals.add(principal)

    def get_principal(self, provider: str, principal_id: str) -> Principal | None:
        """Retrieve a principal by provider and ID."""
        return self._principals.get(provider, principal_id)

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
        """Store a new credential. Delegates to CredentialStore."""
        return self._credentials.add(
            provider=provider, credential_type=credential_type,
            secret_data=secret_data, friendly_name=friendly_name,
            principal_id=principal_id, account_id=account_id,
            derived_from_id=derived_from_id, expires_at=expires_at,
            auto_refresh=auto_refresh, obtained_via=obtained_via,
            raw_data=raw_data,
        )

    def get_credential(self, cred_id: int) -> Credential | None:
        """Retrieve a credential by ID (without secret_data)."""
        return self._credentials.get(cred_id)

    def get_credential_secret(self, cred_id: int) -> str | None:
        """Retrieve the encrypted secret_data for a credential."""
        return self._credentials.get_secret(cred_id)

    def list_credentials(
        self, *, provider: str | None = None, status: str | None = None
    ) -> list[Credential]:
        """List credentials with optional filters."""
        return self._credentials.list(provider=provider, status=status)

    def update_credential_status(self, cred_id: int, status: str) -> None:
        """Update the status of a credential."""
        return self._credentials.update_status(cred_id, status)

    def delete_credential(self, cred_id: int) -> bool:
        """Delete a credential. Deactivates active_credential_id if matched."""
        deleted = self._credentials.delete(cred_id)
        if deleted and self._active_credential_id == cred_id:
            self._active_credential_id = None
        return deleted

    def update_credential_principal(
        self, cred_id: int, principal_id: str, friendly_name: str | None = None
    ) -> None:
        """Link a credential to a discovered principal."""
        return self._credentials.update_principal(cred_id, principal_id, friendly_name)



    # ================================================================
    # API log — delegates to EvidenceStore
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
        """Append an API call to the audit log."""
        return self._evidence.log_api_call(
            provider=provider, action=action, credential_id=credential_id,
            service=service, request_params=request_params,
            response_status=response_status, response_summary=response_summary,
            technique_id=technique_id, duration_ms=duration_ms,
        )

    # ================================================================
    # Evidence — delegates to EvidenceStore
    # ================================================================

    def save_evidence(
        self,
        technique_id: str,
        output_json: str,
        credential_id: int | None = None,
    ) -> int:
        """Save the raw JSON output of a technique to the evidence table."""
        return self._evidence.save(technique_id, output_json, credential_id)

    def list_evidence(self) -> list[dict]:
        """Return all evidence rows ordered by timestamp ascending."""
        return self._evidence.list()

    # ================================================================
    # Findings — delegates to FindingStore
    # ================================================================

    def list_findings(self) -> list[dict]:
        """Return all findings ordered by severity then timestamp."""
        return self._findings.list()

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
        """Persist a security finding. Delegates to FindingStore."""
        return self._findings.add(
            technique_id=technique_id, tactic=tactic, title=title,
            severity=severity, provider=provider, description=description,
            evidence=evidence, mitre_id=mitre_id,
        )

    # ================================================================
    # Assets — delegates to AssetStore
    # ================================================================

    def upsert_compute_instance(self, *, provider: str, instance_id: str, **kwargs) -> None:
        """Insert or update a compute instance record."""
        return self._assets.upsert_compute_instance(
            provider=provider, instance_id=instance_id, **kwargs
        )

    def upsert_network_asset(
        self, *, provider: str, asset_type: str, asset_id: str, **kwargs
    ) -> None:
        """Insert or update a network asset."""
        return self._assets.upsert_network_asset(
            provider=provider, asset_type=asset_type, asset_id=asset_id, **kwargs
        )

    def list_compute_instances(self, *, provider: str | None = None) -> list[dict]:
        """Return all known compute instances, optionally filtered by provider."""
        return self._assets.list_compute_instances(provider=provider)

    # ================================================================
    # Convenience accessors (Phase 2 — eliminate .db reach-through)
    # ================================================================

    @property
    def db_path(self) -> Path:
        """Path to the SQLite database file."""
        return self.db.db_path

    @property
    def workspace_dir(self) -> Path:
        """Parent directory of the workspace database."""
        return self.db.db_path.parent

    def list_agent_ids(self) -> list[str]:
        """Return all agent IDs (used by transport/server for listing)."""
        return self._agents.list_ids()

    def list_stale_agents(self, before_iso: str) -> list[dict]:
        """Return active agents whose last_seen is before the given timestamp."""
        return self._agents.list_stale(before_iso)

    def list_evidence_for_credential(self, credential_id: int, *, limit: int = 5) -> list[dict]:
        """Return recent evidence rows for a specific credential."""
        return self._evidence.list_for_credential(credential_id, limit=limit)

    # ================================================================
    # Lifecycle
    # ================================================================

    def close(self) -> None:
        """Close the workspace database connection."""
        self.db.close()
