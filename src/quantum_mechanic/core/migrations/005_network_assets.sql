-- ================================================================
-- MIGRATION: 005_network_assets.sql
-- ----------------------------------------------------------------
-- PURPOSE:   Store network infrastructure discovered during
--            technique runs (subnets, security groups, VPCs, etc.)
--            so operators can query topology for attack planning.
--
--            Written by enum_compute after each successful run.
--            Idempotent — subsequent runs UPDATE the existing row.
-- ================================================================

CREATE TABLE IF NOT EXISTS network_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id    TEXT    NOT NULL,
    provider        TEXT    NOT NULL,          -- aws | azure | gcp | oci
    asset_type      TEXT    NOT NULL,          -- subnet | security_group | vpc | vnet
    asset_id        TEXT    NOT NULL,          -- provider resource ID
    name            TEXT,                      -- friendly name if available
    region          TEXT,
    metadata        TEXT    NOT NULL DEFAULT '{}',  -- full JSON blob for extra attrs
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),

    FOREIGN KEY (workspace_id) REFERENCES workspace(id),
    UNIQUE (workspace_id, provider, asset_type, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_netasset_workspace ON network_assets(workspace_id);
CREATE INDEX IF NOT EXISTS idx_netasset_type      ON network_assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_netasset_provider  ON network_assets(provider);

-- ----------------------------------------------------------------
-- compute_instances — the authoritative record of every compute
-- instance seen in this engagement. Distinct from evidence (which
-- is raw JSON) — this is a structured queryable record.
-- ----------------------------------------------------------------

CREATE TABLE IF NOT EXISTS compute_instances (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id            TEXT    NOT NULL,
    provider                TEXT    NOT NULL,
    instance_id             TEXT    NOT NULL,  -- i-xxx / vm id / instance ocid
    name                    TEXT,
    state                   TEXT,              -- running | stopped | terminated
    instance_type           TEXT,              -- m5.large / Standard_D2s_v3 / etc
    private_ip              TEXT,
    public_ip               TEXT,
    subnet_id               TEXT,
    image_id                TEXT,
    identity_arn            TEXT,              -- instance profile ARN / managed identity / SA email
    identity_name           TEXT,              -- short name of the identity
    security_group_ids      TEXT,              -- JSON array
    metadata                TEXT    NOT NULL DEFAULT '{}',
    first_seen              TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen               TEXT    NOT NULL DEFAULT (datetime('now')),

    FOREIGN KEY (workspace_id) REFERENCES workspace(id),
    UNIQUE (workspace_id, provider, instance_id)
);

CREATE INDEX IF NOT EXISTS idx_compute_workspace  ON compute_instances(workspace_id);
CREATE INDEX IF NOT EXISTS idx_compute_provider   ON compute_instances(provider);
CREATE INDEX IF NOT EXISTS idx_compute_identity   ON compute_instances(identity_arn);
