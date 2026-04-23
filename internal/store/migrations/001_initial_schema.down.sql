-- Drop indexes first
DROP INDEX IF EXISTS idx_finding_matches_annotation;
DROP INDEX IF EXISTS idx_finding_matches_finding;
DROP INDEX IF EXISTS idx_findings_file;
DROP INDEX IF EXISTS idx_findings_run;
DROP INDEX IF EXISTS idx_runs_project;
DROP INDEX IF EXISTS idx_runs_scanner;
DROP INDEX IF EXISTS idx_runs_experiment;
DROP INDEX IF EXISTS idx_annotations_project;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS finding_matches;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS experiment_projects;
DROP TABLE IF EXISTS experiment_scanners;
DROP TABLE IF EXISTS experiments;
DROP TABLE IF EXISTS scanners;
DROP TABLE IF EXISTS annotations;
DROP TABLE IF EXISTS corpus_projects;
