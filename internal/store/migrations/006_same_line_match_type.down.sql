-- Revert: remove 'same_line' from finding_matches.match_type CHECK constraint.

DELETE FROM finding_matches WHERE match_type = 'same_line';

CREATE TABLE finding_matches_old (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    annotation_id INTEGER NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    match_type    TEXT NOT NULL CHECK(match_type IN ('exact', 'fuzzy', 'category', 'group', 'manual')),
    confidence    REAL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, annotation_id)
);

INSERT INTO finding_matches_old (id, finding_id, annotation_id, match_type, confidence, created_at)
    SELECT id, finding_id, annotation_id, match_type, confidence, created_at FROM finding_matches;

DROP TABLE finding_matches;

ALTER TABLE finding_matches_old RENAME TO finding_matches;

CREATE INDEX idx_finding_matches_finding ON finding_matches(finding_id);
CREATE INDEX idx_finding_matches_annotation ON finding_matches(annotation_id);
