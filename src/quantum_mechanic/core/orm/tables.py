# ================================================================
# MODULE: quantum_mechanic.core.orm.tables
# ----------------------------------------------------------------
# PURPOSE:   SQLAlchemy ORM mapped classes, one per database table.
#            Named 'tables' (not 'models') to avoid confusion with
#            core/store/models.py (the domain dataclasses).
#
# DESIGN:    The ORM classes mirror the schema defined in the SQL
#            migration files exactly. No auto-generation — every
#            column is declared explicitly so diffs are readable.
#
# NOTE:      Stores return domain dataclasses (from store/models.py),
#            not these ORM objects. These are query-only intermediaries.
#
# TABLES (in FK-dependency order):
#   AccountRow         — accounts             (FK stub for credentials)
#   WorkspaceRow       — workspace            (FK stub for all domain tables)
#   CredentialRow      — credentials          (001_initial_schema.sql)
#   ApiLogRow          — api_log              (001_initial_schema.sql)
#   EvidenceRow        — evidence             (002_evidence_table.sql)
#   FindingRow         — findings             (003_findings_table.sql)
#   ComputeInstanceRow — compute_instances    (005_network_assets.sql)
#   NetworkAssetRow    — network_assets       (005_network_assets.sql)
#   AgentRow           — agents               (006_agents.sql)
#   TaskRow            — tasks                (007_tasks.sql)
# ================================================================

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Shared SQLAlchemy declarative base for all QM ORM tables."""


# ================================================================
# accounts (stub — needed so credentials.account_id FK resolves)
# ================================================================

class AccountRow(Base):
    """ORM stub for the 'accounts' table.

    CredentialRow.account_id holds a FK to accounts.id. SQLAlchemy
    must be able to resolve this FK at mapper initialisation time even
    if we never query accounts via the ORM. A minimal stub is sufficient.
    """

    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str | None] = mapped_column(String)
    account_type: Mapped[str | None] = mapped_column(String)
    parent_id: Mapped[str | None] = mapped_column(String)
    metadata_: Mapped[str | None] = mapped_column("metadata", Text)
    created_at: Mapped[str | None] = mapped_column(String)


# ================================================================
# workspace (stub — needed so agents/evidence/findings FK resolves)
# ================================================================

class WorkspaceRow(Base):
    """ORM stub for the 'workspace' table."""

    __tablename__ = "workspace"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    updated_at: Mapped[str] = mapped_column(String, nullable=False)
    scope: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)


# ================================================================
# credentials
# ================================================================

class CredentialRow(Base):
    """ORM mapping for the 'credentials' table.

    Corresponds to the schema defined in 001_initial_schema.sql.
    """

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    credential_type: Mapped[str] = mapped_column(String, nullable=False)
    friendly_name: Mapped[str | None] = mapped_column(String)
    principal_id: Mapped[str | None] = mapped_column(String)
    account_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("accounts.id"), nullable=True
    )
    derived_from_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("credentials.id"), nullable=True
    )
    secret_data: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[str | None] = mapped_column(String)
    auto_refresh: Mapped[bool] = mapped_column(Boolean, default=False)
    last_refreshed: Mapped[str | None] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="active", nullable=False)
    obtained_via: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[str | None] = mapped_column(
        String, server_default=text("(datetime('now'))")
    )
    raw_data: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("idx_credentials_provider", "provider"),
        Index("idx_credentials_status", "status"),
    )


# ================================================================
# api_log
# ================================================================

class ApiLogRow(Base):
    """ORM mapping for the 'api_log' table."""

    __tablename__ = "api_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("(datetime('now'))")
    )
    credential_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    service: Mapped[str | None] = mapped_column(String)
    action: Mapped[str] = mapped_column(String, nullable=False)
    request_params: Mapped[str | None] = mapped_column(Text)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_summary: Mapped[str | None] = mapped_column(Text)
    technique_id: Mapped[str | None] = mapped_column(String)
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        Index("idx_api_log_timestamp", "timestamp"),
        Index("idx_api_log_provider", "provider"),
        Index("idx_api_log_credential", "credential_id"),
    )


# ================================================================
# evidence
# ================================================================

class EvidenceRow(Base):
    """ORM mapping for the 'evidence' table (002_evidence_table.sql)."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[str] = mapped_column(
        String, ForeignKey("workspace.id"), nullable=False
    )
    technique_id: Mapped[str] = mapped_column(String, nullable=False)
    credential_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("credentials.id"), nullable=True
    )
    timestamp: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("(datetime('now'))")
    )
    output_json: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        Index("idx_evidence_workspace", "workspace_id"),
        Index("idx_evidence_technique", "technique_id"),
    )


# ================================================================
# findings
# ================================================================

class FindingRow(Base):
    """ORM mapping for the 'findings' table (003_findings_table.sql)."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[str] = mapped_column(
        String, ForeignKey("workspace.id"), nullable=False
    )
    technique_id: Mapped[str] = mapped_column(String, nullable=False)
    tactic: Mapped[str] = mapped_column(String, nullable=False)
    mitre_id: Mapped[str | None] = mapped_column(String)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("'medium'")
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'{}'")
    )
    created_at: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("(datetime('now'))")
    )

    __table_args__ = (
        Index("idx_findings_workspace", "workspace_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_technique", "technique_id"),
    )


# ================================================================
# compute_instances
# ================================================================

class ComputeInstanceRow(Base):
    """ORM mapping for 'compute_instances' (005_network_assets.sql)."""

    __tablename__ = "compute_instances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[str] = mapped_column(
        String, ForeignKey("workspace.id"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    instance_id: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str | None] = mapped_column(String)
    state: Mapped[str | None] = mapped_column(String)
    instance_type: Mapped[str | None] = mapped_column(String)
    private_ip: Mapped[str | None] = mapped_column(String)
    public_ip: Mapped[str | None] = mapped_column(String)
    subnet_id: Mapped[str | None] = mapped_column(String)
    image_id: Mapped[str | None] = mapped_column(String)
    identity_arn: Mapped[str | None] = mapped_column(String)
    identity_name: Mapped[str | None] = mapped_column(String)
    security_group_ids: Mapped[str] = mapped_column(
        Text, server_default=text("'[]'")
    )
    metadata_: Mapped[str] = mapped_column(
        "metadata", Text, nullable=False, server_default=text("'{}'")
    )
    first_seen: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("(datetime('now'))")
    )
    last_seen: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("(datetime('now'))")
    )

    __table_args__ = (
        Index("idx_compute_workspace", "workspace_id"),
        Index("idx_compute_provider", "provider"),
        Index("idx_compute_identity", "identity_arn"),
    )


# ================================================================
# network_assets
# ================================================================

class NetworkAssetRow(Base):
    """ORM mapping for the 'network_assets' table (005_network_assets.sql)."""

    __tablename__ = "network_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[str] = mapped_column(
        String, ForeignKey("workspace.id"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    asset_type: Mapped[str] = mapped_column(String, nullable=False)
    asset_id: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str | None] = mapped_column(String)
    region: Mapped[str | None] = mapped_column(String)
    metadata_: Mapped[str] = mapped_column(
        "metadata", Text, nullable=False, server_default=text("'{}'")
    )
    first_seen: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("(datetime('now'))")
    )
    last_seen: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("(datetime('now'))")
    )

    __table_args__ = (
        Index("idx_netasset_workspace", "workspace_id"),
        Index("idx_netasset_type", "asset_type"),
        Index("idx_netasset_provider", "provider"),
    )


# ================================================================
# agents
# ================================================================

class AgentRow(Base):
    """ORM mapping for the 'agents' table (006_agents.sql)."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String, ForeignKey("workspace.id"), nullable=False
    )
    hostname: Mapped[str | None] = mapped_column(String)
    username: Mapped[str | None] = mapped_column(String)
    internal_ip: Mapped[str | None] = mapped_column(String)
    platform: Mapped[str | None] = mapped_column(String)
    arch: Mapped[str | None] = mapped_column(String)
    os_version: Mapped[str | None] = mapped_column(String)
    agent_version: Mapped[str | None] = mapped_column(String)
    profile: Mapped[str | None] = mapped_column(String)
    status: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("'active'")
    )
    latency_ms: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    registered_at: Mapped[str] = mapped_column(String, nullable=False)
    last_seen: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        Index("idx_agents_workspace", "workspace_id"),
        Index("idx_agents_status", "status"),
    )


# ================================================================
# tasks
# ================================================================

class TaskRow(Base):
    """ORM mapping for the 'tasks' table (007_tasks.sql)."""

    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String, ForeignKey("workspace.id"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(
        String, ForeignKey("agents.id"), nullable=False
    )
    command: Mapped[str] = mapped_column(String, nullable=False)
    args: Mapped[bytes | None] = mapped_column(LargeBinary)
    status: Mapped[str] = mapped_column(
        String, nullable=False, server_default=text("'pending'")
    )
    output: Mapped[bytes | None] = mapped_column(LargeBinary)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String)

    __table_args__ = (
        Index("idx_tasks_agent", "workspace_id", "agent_id"),
        Index("idx_tasks_status", "workspace_id", "status"),
    )
