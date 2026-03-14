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
# ================================================================

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


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
