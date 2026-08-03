-- Standardized Activity Log Model
-- PURPOSE: Store all technique log events (DEBUG, INFO, SUCCESS, WARN, ERROR)
--          linked to a workspace and technique ID.

CREATE TABLE activity_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id    TEXT NOT NULL,
    technique_id    TEXT NOT NULL,
    level           TEXT NOT NULL,           -- DEBUG, INFO, SUCCESS, WARNING, ERROR
    timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
    message         TEXT NOT NULL,
    data            TEXT,                    -- JSON: optional metadata (e.g. status codes, raw errors)

    FOREIGN KEY (workspace_id) REFERENCES workspace(id)
);

CREATE INDEX idx_activity_workspace ON activity_log(workspace_id);
CREATE INDEX idx_activity_technique ON activity_log(technique_id);
CREATE INDEX idx_activity_level ON activity_log(level);
