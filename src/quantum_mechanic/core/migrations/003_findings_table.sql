-- ================================================================
-- MIGRATION: 003_findings_table.sql
-- ----------------------------------------------------------------
-- PURPOSE:   Create the findings table used by workspace.list_findings()
--            and attack_path.py to build the engagement narrative.
--
--            A finding is a security-relevant observation extracted
--            from technique output — e.g. "AdministratorAccess found",
--            "role chain depth 3", "IMDS v1 exposed".
--
--            Findings are populated by the runner's evidence pipeline
--            after each successful technique execution.
-- ================================================================

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id    TEXT    NOT NULL,
    technique_id    TEXT    NOT NULL,
    tactic          TEXT    NOT NULL,
    mitre_id        TEXT,                              -- e.g. "T1078"
    title           TEXT    NOT NULL,                  -- short human-readable title
    severity        TEXT    NOT NULL DEFAULT 'medium', -- critical|high|medium|low|info
    provider        TEXT    NOT NULL,
    description     TEXT    NOT NULL,                  -- narrative description
    evidence        TEXT    NOT NULL DEFAULT '{}',     -- JSON blob
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),

    FOREIGN KEY (workspace_id) REFERENCES workspace(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_workspace ON findings(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_technique ON findings(technique_id);
