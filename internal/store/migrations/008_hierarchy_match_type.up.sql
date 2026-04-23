-- Add 'hierarchy' to finding_matches.match_type CHECK constraint.
-- 'hierarchy' is a same-file, overlapping-lines match where the finding and
-- annotation use different CWE IDs that are related in the MITRE hierarchy
-- (parent/child, shared ancestor, shared category, or curated pair).
-- Sits between 'exact' and 'fuzzy' in confidence — same line but the CWE
-- needed one hop to match.
-- SQLite can't ALTER a CHECK constraint, so recreate.

CREATE TABLE finding_matches_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    annotation_id INTEGER NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    match_type    TEXT NOT NULL CHECK(match_type IN ('exact', 'hierarchy', 'fuzzy', 'category', 'group', 'manual', 'same_line')),
    confidence    REAL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, annotation_id)
);

INSERT INTO finding_matches_new (id, finding_id, annotation_id, match_type, confidence, created_at)
    SELECT id, finding_id, annotation_id, match_type, confidence, created_at FROM finding_matches;

DROP TABLE finding_matches;

ALTER TABLE finding_matches_new RENAME TO finding_matches;

CREATE INDEX idx_finding_matches_finding ON finding_matches(finding_id);
CREATE INDEX idx_finding_matches_annotation ON finding_matches(annotation_id);
