-- Remove log_path column from runs table
-- SQLite requires table recreation to drop a column

CREATE TABLE runs_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    scanner_id    INTEGER NOT NULL REFERENCES scanners(id) ON DELETE CASCADE,
    project_id    INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    iteration     INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'running', 'completed', 'failed')),
    started_at    DATETIME,
    completed_at  DATETIME,
    duration_ms   INTEGER,
    memory_peak_bytes INTEGER,
    sarif_path    TEXT,
    error_message TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO runs_new (id, experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, error_message, created_at)
SELECT id, experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, error_message, created_at
FROM runs;

DROP TABLE runs;
ALTER TABLE runs_new RENAME TO runs;

CREATE INDEX idx_runs_experiment ON runs(experiment_id);
