-- The projects we scan
CREATE TABLE corpus_projects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    source_url  TEXT,              -- git remote URL (nullable for local-only)
    local_path  TEXT NOT NULL,     -- path on disk
    language    TEXT,              -- primary language (e.g., "java", "python")
    commit_sha  TEXT,              -- pinned git commit for reproducibility
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Ground-truth annotations: known vulnerabilities in the corpus
CREATE TABLE annotations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    file_path     TEXT NOT NULL,       -- relative to project root
    start_line    INTEGER NOT NULL,
    end_line      INTEGER,             -- nullable for single-line findings
    cwe_id        TEXT,                -- e.g., "CWE-89"
    category      TEXT NOT NULL,       -- e.g., "sql-injection", "xss"
    severity      TEXT NOT NULL,       -- "critical", "high", "medium", "low", "info"
    description   TEXT,
    status        TEXT NOT NULL DEFAULT 'tp' CHECK(status IN ('tp', 'fp', 'disputed')),
    annotated_by  TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Registered scanners
CREATE TABLE scanners (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,       -- e.g., "semgrep"
    version       TEXT NOT NULL,       -- e.g., "1.50.0"
    docker_image  TEXT NOT NULL,       -- e.g., "benchmrk/scanner-semgrep:1.50.0"
    config_json   TEXT,                -- scanner-specific config (nullable)
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, version)
);

-- An experiment: a planned benchmarking configuration
CREATE TABLE experiments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    description TEXT,
    iterations  INTEGER NOT NULL DEFAULT 1,  -- how many times to repeat each scan
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Which scanners are part of this experiment
CREATE TABLE experiment_scanners (
    experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    scanner_id    INTEGER NOT NULL REFERENCES scanners(id) ON DELETE CASCADE,
    PRIMARY KEY (experiment_id, scanner_id)
);

-- Which projects are part of this experiment
CREATE TABLE experiment_projects (
    experiment_id INTEGER NOT NULL REFERENCES experiments(id) ON DELETE CASCADE,
    project_id    INTEGER NOT NULL REFERENCES corpus_projects(id) ON DELETE CASCADE,
    PRIMARY KEY (experiment_id, project_id)
);

-- Individual scan execution
CREATE TABLE runs (
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
    sarif_path    TEXT,               -- path to raw SARIF output file
    error_message TEXT,               -- populated on failure
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Parsed findings from scanner output
CREATE TABLE findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    rule_id     TEXT,                 -- scanner's rule identifier
    file_path   TEXT NOT NULL,        -- relative to project root
    start_line  INTEGER NOT NULL,
    end_line    INTEGER,
    cwe_id      TEXT,
    severity    TEXT,
    message     TEXT,
    snippet     TEXT,                 -- code snippet from SARIF
    fingerprint TEXT,                 -- for deduplication across runs
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Matching findings to ground-truth annotations
CREATE TABLE finding_matches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    annotation_id INTEGER NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
    match_type    TEXT NOT NULL CHECK(match_type IN ('exact', 'fuzzy', 'category', 'group', 'manual')),
    confidence    REAL,              -- 0.0-1.0 for fuzzy matches
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_id, annotation_id)
);

-- Indexes
CREATE INDEX idx_annotations_project ON annotations(project_id);
CREATE INDEX idx_runs_experiment ON runs(experiment_id);
CREATE INDEX idx_runs_scanner ON runs(scanner_id);
CREATE INDEX idx_runs_project ON runs(project_id);
CREATE INDEX idx_findings_run ON findings(run_id);
CREATE INDEX idx_findings_file ON findings(file_path);
CREATE INDEX idx_finding_matches_finding ON finding_matches(finding_id);
CREATE INDEX idx_finding_matches_annotation ON finding_matches(annotation_id);
