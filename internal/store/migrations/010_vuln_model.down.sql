-- Reverting the vuln model means reconstructing annotations from
-- evidence+vuln rows. Single-evidence vulns round-trip cleanly.
-- Multi-evidence vulns become groups again; the first CWE in the
-- vuln's set is arbitrarily assigned to each member (lossy — the
-- per-member CWE is gone).
--
-- finding_matches is truncated in both directions; rescore after.

PRAGMA foreign_keys = OFF;

CREATE TABLE annotations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    file_path     TEXT NOT NULL,
    start_line    INTEGER NOT NULL,
    end_line      INTEGER,
    cwe_id        TEXT,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    description   TEXT,
    status        TEXT NOT NULL DEFAULT 'valid' CHECK(status IN ('valid', 'invalid', 'disputed')),
    annotated_by  TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE annotation_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    name        TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE annotation_group_members (
    group_id      INTEGER NOT NULL REFERENCES annotation_groups(id) ON DELETE CASCADE,
    annotation_id INTEGER NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    role          TEXT NOT NULL DEFAULT 'related' CHECK(role IN ('source', 'sink', 'related')),
    PRIMARY KEY (group_id, annotation_id)
);

-- Every evidence row → one annotation. ID preserved.
INSERT INTO annotations (id, project_id, file_path, start_line, end_line, cwe_id, category, severity, description, status, annotated_by, created_at, updated_at)
SELECT
    e.id,
    v.project_id,
    e.file_path, e.start_line, e.end_line,
    (SELECT cwe_id FROM vuln_cwes WHERE vuln_id = v.id ORDER BY cwe_id LIMIT 1),
    e.category, e.severity,
    v.description,
    v.status,
    (SELECT annotated_by FROM vuln_annotators WHERE vuln_id = v.id ORDER BY created_at LIMIT 1),
    e.created_at,
    v.updated_at
FROM vuln_evidence e
JOIN vulnerabilities v ON v.id = e.vuln_id;

-- Multi-evidence vulns → groups.
INSERT INTO annotation_groups (id, project_id, name, created_at)
SELECT v.id, v.project_id, v.name, v.created_at
FROM vulnerabilities v
WHERE (SELECT COUNT(*) FROM vuln_evidence WHERE vuln_id = v.id) > 1;

INSERT INTO annotation_group_members (group_id, annotation_id, role)
SELECT e.vuln_id, e.id,
       CASE e.role WHEN 'helper' THEN 'related' ELSE e.role END
FROM vuln_evidence e
WHERE e.vuln_id IN (SELECT id FROM annotation_groups);

-- Retarget finding_matches back.
DROP TABLE finding_matches;
CREATE TABLE finding_matches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    annotation_id INTEGER NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    match_type    TEXT NOT NULL CHECK(match_type IN ('exact', 'hierarchy', 'fuzzy', 'category', 'group', 'manual', 'same_line')),
    confidence    REAL,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, annotation_id)
);
CREATE INDEX idx_finding_matches_finding    ON finding_matches(finding_id);
CREATE INDEX idx_finding_matches_annotation ON finding_matches(annotation_id);

CREATE INDEX idx_annotations_project              ON annotations(project_id);
CREATE INDEX idx_annotation_groups_project        ON annotation_groups(project_id);
CREATE INDEX idx_annotation_group_members_annotation ON annotation_group_members(annotation_id);

DROP TABLE vuln_annotators;
DROP TABLE vuln_cwes;
DROP TABLE vuln_evidence;
DROP TABLE vulnerabilities;

PRAGMA foreign_keys = ON;
