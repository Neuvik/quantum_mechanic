-- ================================================================
-- MIGRATION: 004_findings_unique.sql
-- ----------------------------------------------------------------
-- PURPOSE:   Add a unique constraint on (workspace_id, technique_id, title)
--            so repeated runs of the same technique don't stack up
--            duplicate findings rows for the same flag.
--
--            SQLite doesn't support ADD CONSTRAINT on existing tables,
--            so we recreate it with the constraint baked in.
-- ================================================================

-- Create the new constrained table.
CREATE TABLE IF NOT EXISTS findings_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id    TEXT    NOT NULL,
    technique_id    TEXT    NOT NULL,
    tactic          TEXT    NOT NULL,
    mitre_id        TEXT,
    title           TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'medium',
    provider        TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    evidence        TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),

    FOREIGN KEY (workspace_id) REFERENCES workspace(id),
    UNIQUE (workspace_id, technique_id, title)
);

-- Copy existing data (deduplicated by keeping first occurrence).
INSERT OR IGNORE INTO findings_new
    (id, workspace_id, technique_id, tactic, mitre_id, title,
     severity, provider, description, evidence, created_at)
SELECT
    id, workspace_id, technique_id, tactic, mitre_id, title,
    severity, provider, description, evidence, created_at
FROM findings;

-- Swap tables.
DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

-- Recreate indexes.
CREATE INDEX IF NOT EXISTS idx_findings_workspace ON findings(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_technique ON findings(technique_id);
