package store

import (
	"testing"
)

func TestNewStore(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	if s.db == nil {
		t.Error("expected db to be non-nil")
	}
}

func TestMigrate(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}

	// Verify corpus_projects table exists
	var tableName string
	err = s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='corpus_projects'").Scan(&tableName)
	if err != nil {
		t.Fatalf("corpus_projects table not found: %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	// Run migrate twice - should not error
	if err := s.Migrate(); err != nil {
		t.Fatalf("first Migrate() failed: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("second Migrate() failed: %v", err)
	}
}

func TestMigrateDown(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}

	if err := s.MigrateDown(); err != nil {
		t.Fatalf("MigrateDown() failed: %v", err)
	}

	// Verify tables are gone
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='corpus_projects'").Scan(&count)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 0 {
		t.Error("expected corpus_projects table to be dropped")
	}
}

func TestWALModeEnabled(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	var journalMode string
	err = s.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		t.Fatalf("query journal_mode failed: %v", err)
	}
	// In-memory databases use "memory" instead of "wal"
	if journalMode != "wal" && journalMode != "memory" {
		t.Errorf("expected journal_mode 'wal' or 'memory', got %q", journalMode)
	}
}

func TestForeignKeysEnforced(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}

	// Try to insert a vulnerability with a non-existent project_id - should fail
	_, err = s.db.Exec(`
		INSERT INTO vulnerabilities (project_id, name, criticality, status)
		VALUES (9999, 'test', 'should', 'valid')
	`)
	if err == nil {
		t.Error("expected foreign key violation error, got nil")
	}
}

func TestAllTablesCreated(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}

	expectedTables := []string{
		"corpus_projects",
		"vulnerabilities",
		"vuln_evidence",
		"vuln_cwes",
		"vuln_annotators",
		"scanners",
		"experiments",
		"experiment_scanners",
		"experiment_projects",
		"runs",
		"findings",
		"finding_matches",
	}

	droppedTables := []string{"annotations", "annotation_groups", "annotation_group_members"}
	for _, table := range droppedTables {
		var name string
		err := s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err == nil {
			t.Errorf("table %q should have been dropped by migration 010, still present", table)
		}
	}

	for _, table := range expectedTables {
		var name string
		err := s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestAllIndexesCreated(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}

	expectedIndexes := []string{
		"idx_vulnerabilities_project",
		"idx_vuln_evidence_vuln",
		"idx_vuln_evidence_file",
		"idx_vuln_cwes_vuln",
		"idx_runs_experiment",
		"idx_runs_scanner",
		"idx_runs_project",
		"idx_findings_run",
		"idx_findings_file",
		"idx_finding_matches_finding",
		"idx_finding_matches_evidence",
	}

	for _, idx := range expectedIndexes {
		var name string
		err := s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&name)
		if err != nil {
			t.Errorf("index %q not found: %v", idx, err)
		}
	}
}

func TestCascadeDelete(t *testing.T) {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer s.Close()

	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}

	// Insert a project
	res, err := s.db.Exec(`INSERT INTO corpus_projects (name, local_path) VALUES ('test', '/tmp/test')`)
	if err != nil {
		t.Fatalf("insert project failed: %v", err)
	}
	projectID, _ := res.LastInsertId()

	// Insert a vulnerability with evidence to verify the cascade chain
	// project → vuln → evidence works end to end.
	res, err = s.db.Exec(`
		INSERT INTO vulnerabilities (project_id, name, criticality, status)
		VALUES (?, 'test', 'should', 'valid')
	`, projectID)
	if err != nil {
		t.Fatalf("insert vuln failed: %v", err)
	}
	vid, _ := res.LastInsertId()
	_, err = s.db.Exec(`
		INSERT INTO vuln_evidence (vuln_id, file_path, start_line, role, category, severity)
		VALUES (?, 'test.go', 1, 'sink', 'sql-injection', 'high')
	`, vid)
	if err != nil {
		t.Fatalf("insert evidence failed: %v", err)
	}

	_, err = s.db.Exec("DELETE FROM corpus_projects WHERE id = ?", projectID)
	if err != nil {
		t.Fatalf("delete project failed: %v", err)
	}

	var vc, ec int
	s.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities WHERE project_id = ?", projectID).Scan(&vc)
	s.db.QueryRow("SELECT COUNT(*) FROM vuln_evidence WHERE vuln_id = ?", vid).Scan(&ec)
	if vc != 0 || ec != 0 {
		t.Errorf("cascade delete incomplete: %d vulns, %d evidence remain", vc, ec)
	}
}
