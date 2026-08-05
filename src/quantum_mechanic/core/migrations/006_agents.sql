-- ================================================================
-- MIGRATION: 006_agents
-- ----------------------------------------------------------------
-- PURPOSE:   Creates the tracking table for remote agents
--            connected to a QM remote execution plane.
-- ================================================================

CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspace(id),
    hostname TEXT,
    username TEXT,
    internal_ip TEXT,
    platform TEXT,
    arch TEXT,
    os_version TEXT,
    agent_version TEXT,
    profile TEXT,
    status TEXT NOT NULL DEFAULT 'active', -- 'active', 'inactive', 'revoked'
    latency_ms INTEGER DEFAULT 0,
    registered_at TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL
);

CREATE INDEX idx_agents_workspace ON agents(workspace_id);
CREATE INDEX idx_agents_status ON agents(status);
