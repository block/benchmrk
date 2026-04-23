-- Support locally-installed scanners (not Docker-based)
ALTER TABLE scanners ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'docker' CHECK(execution_mode IN ('docker', 'local'));
ALTER TABLE scanners ADD COLUMN executable_path TEXT;
