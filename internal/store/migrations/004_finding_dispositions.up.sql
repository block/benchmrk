CREATE TABLE finding_dispositions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    disposition TEXT NOT NULL CHECK(disposition IN ('tp', 'fp', 'needs_review')),
    notes       TEXT,
    reviewed_by TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id)
);

CREATE INDEX idx_finding_dispositions_finding ON finding_dispositions(finding_id);
