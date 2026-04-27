-- Revert annotation status values: valid → tp, invalid → fp

CREATE TABLE annotations_old (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    file_path     TEXT NOT NULL,
    start_line    INTEGER NOT NULL,
    end_line      INTEGER,
    cwe_id        TEXT,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    description   TEXT,
    status        TEXT NOT NULL DEFAULT 'tp' CHECK(status IN ('tp', 'fp', 'disputed')),
    annotated_by  TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO annotations_old (id, project_id, file_path, start_line, end_line, cwe_id, category, severity, description, status, annotated_by, created_at, updated_at)
SELECT id, project_id, file_path, start_line, end_line, cwe_id, category, severity, description,
    CASE status WHEN 'valid' THEN 'tp' WHEN 'invalid' THEN 'fp' ELSE status END,
    annotated_by, created_at, updated_at
FROM annotations;

DROP TABLE annotations;
ALTER TABLE annotations_old RENAME TO annotations;

CREATE INDEX idx_annotations_project ON annotations(project_id);
