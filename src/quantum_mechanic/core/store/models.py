# ================================================================
# MODULE: quantum_mechanic.core.store.models
# ----------------------------------------------------------------
# PURPOSE:   Shared dataclasses for all workspace domain stores.
#            Extracted from workspace.py (RC-2 refactor) so each
#            store module can import without circular references.
#
# CONSUMERS: workspace.py re-exports everything from here so that
#            existing callers using:
#            `from quantum_mechanic.core.workspace import Credential`
#            continue to work without any changes.
# ================================================================

from __future__ import annotations

from dataclasses import dataclass


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
    # It is only accessed through the credential store to
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
    """Represents a remote agent."""

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
    """Represents a job queued for a remote agent."""

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
