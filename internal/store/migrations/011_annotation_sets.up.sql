-- Track annotation set versions so "why did the numbers change" is
-- answerable. Each import writes a row; compare's annotation_hash on
-- the run row joins here to recover the source file and git SHA.
--
-- The hash is the same one analysis.annotationHash computes and stamps
-- on runs — so a run's annotation_hash is a foreign key into this table
-- (not declared as one: imports are optional, and pre-011 runs have
-- hashes with no corresponding row).

CREATE TABLE annotation_sets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    hash        TEXT NOT NULL,     -- matches runs.annotation_hash
    source_path TEXT,              -- the JSON file imported from (nullable: API imports)
    git_sha     TEXT,              -- commit of source_path at import time (best-effort)
    vuln_count  INTEGER NOT NULL,  -- snapshot for quick display
    format      TEXT NOT NULL      -- 'legacy' or 'vulnerability'
                CHECK(format IN ('legacy', 'vulnerability')),
    imported_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Not UNIQUE(project_id, hash): re-importing the same file is a
    -- legitimate operation (e.g. after --replace) and deserves its own
    -- history row.
    -- The diff command reads pairs of these by hash.
    UNIQUE(id)
);

CREATE INDEX idx_annotation_sets_project ON annotation_sets(project_id);
CREATE INDEX idx_annotation_sets_hash    ON annotation_sets(hash);
