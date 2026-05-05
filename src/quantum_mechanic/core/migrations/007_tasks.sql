-- ================================================================
-- MIGRATION: 007_tasks
-- ----------------------------------------------------------------
-- PURPOSE:   Creates the tracking table for Neutrino agent tasks.
-- ================================================================

CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspace(id),
    agent_id TEXT NOT NULL REFERENCES agents(id),
    command TEXT NOT NULL,
    args BLOB,
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
    output BLOB,
    error TEXT,
    created_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP
);

CREATE INDEX idx_tasks_agent ON tasks(workspace_id, agent_id);
CREATE INDEX idx_tasks_status ON tasks(workspace_id, status);
