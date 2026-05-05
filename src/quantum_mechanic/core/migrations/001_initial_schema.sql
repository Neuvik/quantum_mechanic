-- ================================================================
-- MIGRATION: 001_initial_schema.sql
-- ----------------------------------------------------------------
-- PURPOSE:   Create the initial workspace database schema for the
--            Quantum Mechanic MVP.
--
-- TABLES:    workspace, accounts, credentials, principals, api_log
--
-- NOTE:      Additional tables (permissions, resources,
--            network_exposure, relationships, findings, tags)
--            will be added in future migrations as techniques
--            require them.
-- ================================================================

-- ----------------------------------------------------------------
-- workspace: Engagement metadata. One row per workspace.
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workspace (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    scope       TEXT,  -- JSON: target accounts, subscriptions, projects
    notes       TEXT
);

-- ----------------------------------------------------------------
-- accounts: Cloud tenants / accounts / subscriptions / projects.
-- The organizational root for all entities.
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,  -- Provider-native ID (account number, subscription ID, project ID, OCID)
    provider    TEXT NOT NULL,     -- aws, azure, gcp, oci
    name        TEXT,             -- Friendly name ("acme-prod", "Acme Corp")
    account_type TEXT,            -- account, subscription, tenant, project, tenancy, compartment
    parent_id   TEXT,             -- Parent account (e.g., Azure subscription → tenant)
    metadata    TEXT,             -- JSON: additional provider-specific info
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),

    FOREIGN KEY (parent_id) REFERENCES accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(provider);

-- ----------------------------------------------------------------
-- credentials: Every token, key, and session obtained during the
-- engagement. Tracks lifecycle, provenance, and auto-refresh.
--
-- SECURITY: secret_data is encrypted at rest using Fernet
-- symmetric encryption.
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT NOT NULL,           -- aws, azure, gcp, oci
    credential_type TEXT NOT NULL,           -- access_key, assumed_role, refresh_token,
                                            -- service_account_key, session_token, api_key
    friendly_name   TEXT,                    -- Human-readable ("BackupAdminRole in acme-prod")
    principal_id    TEXT,                    -- FK to principals (who this authenticates as)
    account_id      TEXT,                    -- FK to accounts (which tenant/account)
    derived_from_id INTEGER,                -- FK to credentials (provenance chain)
    secret_data     TEXT NOT NULL,           -- Encrypted credential material
    expires_at      TEXT,                    -- ISO 8601 expiration (NULL = never)
    auto_refresh    INTEGER NOT NULL DEFAULT 0,  -- Can this be auto-refreshed?
    last_refreshed  TEXT,                    -- Last refresh timestamp
    status          TEXT NOT NULL DEFAULT 'active',  -- active, expiring, expired, revoked
    obtained_via    TEXT,                    -- How it was obtained
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    raw_data        TEXT,                    -- JSON: full API response for deep inspection

    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (derived_from_id) REFERENCES credentials(id)
);

CREATE INDEX IF NOT EXISTS idx_credentials_provider ON credentials(provider);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);

-- ----------------------------------------------------------------
-- principals: Cloud identities — users, roles, service accounts,
-- service principals, managed identities, groups.
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS principals (
    id              TEXT NOT NULL,           -- Provider-native ID (ARN, object ID, email, OCID)
    provider        TEXT NOT NULL,           -- aws, azure, gcp, oci
    account_id      TEXT,                    -- FK to accounts
    principal_type  TEXT NOT NULL,           -- user, role, service_account, service_principal,
                                            -- managed_identity, group, dynamic_group
    friendly_name   TEXT,                    -- Human-readable ("BackupAdminRole")
    is_admin_equivalent INTEGER NOT NULL DEFAULT 0,
    last_enumerated TEXT,                    -- When permissions were last checked
    notes           TEXT,                    -- Operator annotations
    raw_data        TEXT,                    -- JSON: full API response
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),

    PRIMARY KEY (provider, id),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_principals_type ON principals(principal_type);
CREATE INDEX IF NOT EXISTS idx_principals_account ON principals(account_id);

-- ----------------------------------------------------------------
-- api_log: Append-only log of every API call made during the
-- engagement. Evidence chain for reporting and chain of custody.
--
-- This table is NEVER modified after insert — it is the audit
-- trail of everything QM did.
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
    credential_id   INTEGER,                -- FK to credentials (which cred was used)
    provider        TEXT NOT NULL,           -- aws, azure, gcp, oci
    service         TEXT,                    -- iam, ec2, s3, compute, etc.
    action          TEXT NOT NULL,           -- API action (DescribeInstances, etc.)
    request_params  TEXT,                    -- JSON: what was sent
    response_status INTEGER,                -- HTTP status code
    response_summary TEXT,                   -- Brief response description
    technique_id    TEXT,                    -- Which technique made this call
    duration_ms     INTEGER,                -- How long the call took

    FOREIGN KEY (credential_id) REFERENCES credentials(id)
);

CREATE INDEX IF NOT EXISTS idx_api_log_timestamp ON api_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_api_log_provider ON api_log(provider);
CREATE INDEX IF NOT EXISTS idx_api_log_credential ON api_log(credential_id);
