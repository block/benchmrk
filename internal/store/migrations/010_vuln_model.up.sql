-- Schema inversion: annotations → vulnerabilities + evidence.
--
-- WHY
--   A vulnerability is one truth ("tasks resource has no authz") that
--   may be evidenced at many locations (GET, DELETE, PATCH handlers).
--   The old schema made the location primary and bolted groups on top;
--   this makes the vulnerability primary and locations are attributes
--   of it. One match to any evidence row satisfies the vulnerability.
--
--   CWE becomes a set. The same password-change-without-verify bug is
--   correctly described by CWE-620, CWE-352, or CWE-640 depending on
--   which angle you look from. The annotation set shouldn't have to
--   guess which one the scanner will pick.
--
-- COMPAT
--   Evidence row IDs == old annotation IDs. The Go-level store.Annotation
--   type stays; its CRUD is re-backed by queries against vuln_evidence
--   joined to vulnerabilities. GetAnnotation(42) still returns the thing
--   that was annotation 42. Reports, web UI, and API keep working
--   untouched.
--
-- DATA TRANSFORM
--   solo annotation    → one vuln, one evidence, one cwe
--   annotation_group   → one vuln; each member → one evidence;
--                        distinct member CWEs → cwe rows
--   finding_matches    → truncated (it's derived; recomputed on next compare)
--
-- TP ACCOUNTING CHANGES
--   Under the old model, a 3-member group with 1 matched member scored
--   3 TP (direct + 2 group-rescued). Under this model, that's 1
--   satisfied vulnerability = 1 TP. More correct, but every historical
--   F1 is now incomparable. MatcherVersion bumps to 3 to mark the
--   boundary.

PRAGMA foreign_keys = OFF;

-- ────────────────────────────────────────────────────────────────────
-- New tables
-- ────────────────────────────────────────────────────────────────────

CREATE TABLE vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    -- must:   any competent SAST tool should find this. Missing it is a
    --         defect in the tool, not a judgment call.
    -- should: reasonable to expect; missing it is a recall gap.
    -- may:    defensible either way. Hardening gaps, contested severity.
    criticality TEXT NOT NULL DEFAULT 'should'
                CHECK(criticality IN ('must', 'should', 'may')),
    status      TEXT NOT NULL DEFAULT 'valid'
                CHECK(status IN ('valid', 'invalid', 'disputed')),
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vuln_evidence (
    -- id space inherits from old annotations.id so the compat shim can
    -- do GetAnnotation(id) → SELECT ... WHERE evidence.id = id without
    -- a mapping table. New rows after migration use AUTOINCREMENT from
    -- wherever the sequence left off.
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_id     INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    start_line  INTEGER NOT NULL,
    end_line    INTEGER,
    -- role is informational; the matcher treats all evidence equally.
    -- Kept so a future matcher can weight sink > helper.
    role        TEXT NOT NULL DEFAULT 'sink'
                CHECK(role IN ('source', 'sink', 'helper', 'related')),
    -- category and severity are per-evidence because the compat shim
    -- needs them to synthesize Annotation rows, and the old schema had
    -- them per-annotation. Semantically they belong on the vuln, but
    -- the practical cost of duplicating them here is zero and the
    -- compat cost of moving them is high.
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vuln_cwes (
    vuln_id     INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cwe_id      TEXT NOT NULL,  -- "CWE-89" form; normalized at match time
    PRIMARY KEY (vuln_id, cwe_id)
);

CREATE TABLE vuln_annotators (
    vuln_id      INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    annotated_by TEXT NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vuln_id, annotated_by)
);

CREATE INDEX idx_vulnerabilities_project ON vulnerabilities(project_id);
CREATE INDEX idx_vuln_evidence_vuln      ON vuln_evidence(vuln_id);
CREATE INDEX idx_vuln_evidence_file      ON vuln_evidence(file_path);
CREATE INDEX idx_vuln_cwes_vuln          ON vuln_cwes(vuln_id);

-- ────────────────────────────────────────────────────────────────────
-- Migrate group annotations → one vuln per group
-- ────────────────────────────────────────────────────────────────────

-- Vuln IDs for groups: offset by max(annotations.id) so they don't
-- collide with the solo-annotation vuln IDs below (which reuse
-- annotation IDs for easy mental mapping).
INSERT INTO vulnerabilities (id, project_id, name, description, criticality, status, created_at, updated_at)
SELECT
    g.id + (SELECT COALESCE(MAX(id), 0) FROM annotations),
    g.project_id,
    COALESCE(g.name, 'group-' || g.id),
    -- Description: concatenate member descriptions. Crude, but better
    -- than dropping them. A human can clean it up post-migration.
    (SELECT GROUP_CONCAT(a.description, ' // ')
     FROM annotation_group_members m JOIN annotations a ON a.id = m.annotation_id
     WHERE m.group_id = g.id AND a.description IS NOT NULL),
    'should',
    -- Status: valid if ANY member is valid (the group is a real vuln if
    -- any instance of it is real). Invalid only if every member is.
    CASE WHEN EXISTS (
        SELECT 1 FROM annotation_group_members m JOIN annotations a ON a.id = m.annotation_id
        WHERE m.group_id = g.id AND a.status = 'valid'
    ) THEN 'valid' ELSE 'invalid' END,
    g.created_at,
    g.created_at
FROM annotation_groups g;

-- Evidence rows: one per group member, preserving the old annotation ID.
INSERT INTO vuln_evidence (id, vuln_id, file_path, start_line, end_line, role, category, severity, created_at)
SELECT
    a.id,
    m.group_id + (SELECT COALESCE(MAX(id), 0) FROM annotations),
    a.file_path, a.start_line, a.end_line,
    -- annotation_group_members.role uses the same vocabulary; map
    -- 'related' → 'related', 'source'/'sink' pass through.
    m.role,
    a.category, a.severity, a.created_at
FROM annotation_group_members m
JOIN annotations a ON a.id = m.annotation_id;

-- CWE set: distinct CWEs across group members.
INSERT INTO vuln_cwes (vuln_id, cwe_id)
SELECT DISTINCT
    m.group_id + (SELECT COALESCE(MAX(id), 0) FROM annotations),
    a.cwe_id
FROM annotation_group_members m
JOIN annotations a ON a.id = m.annotation_id
WHERE a.cwe_id IS NOT NULL AND a.cwe_id != '';

-- Annotators: distinct across group members.
INSERT INTO vuln_annotators (vuln_id, annotated_by, created_at)
SELECT DISTINCT
    m.group_id + (SELECT COALESCE(MAX(id), 0) FROM annotations),
    a.annotated_by,
    MIN(a.created_at)
FROM annotation_group_members m
JOIN annotations a ON a.id = m.annotation_id
WHERE a.annotated_by IS NOT NULL AND a.annotated_by != ''
GROUP BY m.group_id, a.annotated_by;

-- ────────────────────────────────────────────────────────────────────
-- Migrate solo annotations → one vuln each
-- ────────────────────────────────────────────────────────────────────

INSERT INTO vulnerabilities (id, project_id, name, description, criticality, status, created_at, updated_at)
SELECT
    a.id,  -- reuse annotation ID as vuln ID
    a.project_id,
    -- Synthesize a name from category + location. Not pretty, but
    -- better than 'vuln-42'. A human pass can rename.
    a.category || ' @ ' || a.file_path || ':' || a.start_line,
    a.description,
    'should',
    a.status,
    a.created_at,
    a.updated_at
FROM annotations a
WHERE a.id NOT IN (SELECT annotation_id FROM annotation_group_members);

INSERT INTO vuln_evidence (id, vuln_id, file_path, start_line, end_line, role, category, severity, created_at)
SELECT
    a.id,   -- evidence ID == old annotation ID (compat)
    a.id,   -- vuln ID == same (solo: one-to-one)
    a.file_path, a.start_line, a.end_line,
    'sink',
    a.category, a.severity, a.created_at
FROM annotations a
WHERE a.id NOT IN (SELECT annotation_id FROM annotation_group_members);

INSERT INTO vuln_cwes (vuln_id, cwe_id)
SELECT a.id, a.cwe_id
FROM annotations a
WHERE a.id NOT IN (SELECT annotation_id FROM annotation_group_members)
  AND a.cwe_id IS NOT NULL AND a.cwe_id != '';

INSERT INTO vuln_annotators (vuln_id, annotated_by, created_at)
SELECT a.id, a.annotated_by, a.created_at
FROM annotations a
WHERE a.id NOT IN (SELECT annotation_id FROM annotation_group_members)
  AND a.annotated_by IS NOT NULL AND a.annotated_by != '';

-- ────────────────────────────────────────────────────────────────────
-- Retarget finding_matches: annotation_id → evidence_id
-- ────────────────────────────────────────────────────────────────────
--
-- Derived state; truncated. Next compare recomputes against evidence.
-- The IDs would map 1:1 (evidence.id == old annotation.id) so the rows
-- would survive a rename, but the TP-accounting semantics changed, so
-- forcing a rescore is the honest thing to do.

DROP TABLE finding_matches;

CREATE TABLE finding_matches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES vuln_evidence(id) ON DELETE CASCADE,
    match_type  TEXT NOT NULL CHECK(match_type IN ('exact', 'hierarchy', 'fuzzy', 'category', 'group', 'manual', 'same_line')),
    confidence  REAL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, evidence_id)
);

CREATE INDEX idx_finding_matches_finding  ON finding_matches(finding_id);
CREATE INDEX idx_finding_matches_evidence ON finding_matches(evidence_id);

-- ────────────────────────────────────────────────────────────────────
-- Drop old tables
-- ────────────────────────────────────────────────────────────────────

DROP TABLE annotation_group_members;
DROP TABLE annotation_groups;
DROP TABLE annotations;

-- AUTOINCREMENT sequences: vuln_evidence inherited IDs from annotations,
-- so bump its sequence past the max we inserted. Same for vulnerabilities
-- (group vulns used IDs past max(annotations.id)).
UPDATE sqlite_sequence
   SET seq = (SELECT COALESCE(MAX(id), 0) FROM vuln_evidence)
 WHERE name = 'vuln_evidence';
UPDATE sqlite_sequence
   SET seq = (SELECT COALESCE(MAX(id), 0) FROM vulnerabilities)
 WHERE name = 'vulnerabilities';

PRAGMA foreign_keys = ON;
