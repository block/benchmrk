-- Revert 008: drop 'hierarchy' from the CHECK constraint.
-- Any rows with match_type='hierarchy' are remapped to 'same_line' — the
-- nearest pre-008 tier for "same location, different CWE".

CREATE TABLE finding_matches_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    annotation_id INTEGER NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    match_type    TEXT NOT NULL CHECK(match_type IN ('exact', 'fuzzy', 'category', 'group', 'manual', 'same_line')),
    confidence    REAL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, annotation_id)
);

INSERT INTO finding_matches_new (id, finding_id, annotation_id, match_type, confidence, created_at)
    SELECT id, finding_id, annotation_id,
           CASE match_type WHEN 'hierarchy' THEN 'same_line' ELSE match_type END,
           confidence, created_at
    FROM finding_matches;

DROP TABLE finding_matches;

ALTER TABLE finding_matches_new RENAME TO finding_matches;

CREATE INDEX idx_finding_matches_finding ON finding_matches(finding_id);
CREATE INDEX idx_finding_matches_annotation ON finding_matches(annotation_id);
