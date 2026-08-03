-- ================================================================
-- MIGRATION: 002_evidence_table.sql
-- ----------------------------------------------------------------
-- PURPOSE:   Create the evidence table to store raw JSON output
--            from executed techniques. This serves as the primary
--            context for the Autonomous RAG Agent (Phase 11).
-- ================================================================

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id    TEXT NOT NULL,
    technique_id    TEXT NOT NULL,
    credential_id   INTEGER,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
    output_json     TEXT NOT NULL,           -- JSON: full technique output

    FOREIGN KEY (workspace_id) REFERENCES workspace(id),
    FOREIGN KEY (credential_id) REFERENCES credentials(id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_workspace ON evidence(workspace_id);
CREATE INDEX IF NOT EXISTS idx_evidence_technique ON evidence(technique_id);
