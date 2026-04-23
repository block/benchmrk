package store

import (
	"context"
	"database/sql"
	"testing"
)

func TestCreateGetExperimentRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	e := &Experiment{
		Name:        "test-experiment",
		Description: sql.NullString{String: "A test experiment", Valid: true},
		Iterations:  3,
	}

	id, err := s.CreateExperiment(ctx, e)
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	got, err := s.GetExperiment(ctx, id)
	if err != nil {
		t.Fatalf("GetExperiment() failed: %v", err)
	}
	if got.Name != e.Name {
		t.Errorf("Name = %q, want %q", got.Name, e.Name)
	}
	if got.Description != e.Description {
		t.Errorf("Description = %v, want %v", got.Description, e.Description)
	}
	if got.Iterations != e.Iterations {
		t.Errorf("Iterations = %d, want %d", got.Iterations, e.Iterations)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestGetExperimentNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.GetExperiment(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("GetExperiment() error = %v, want ErrNotFound", err)
	}
}

func TestListExperiments(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Create multiple experiments
	for _, name := range []string{"exp-a", "exp-b", "exp-c"} {
		_, err := s.CreateExperiment(ctx, &Experiment{Name: name, Iterations: 1})
		if err != nil {
			t.Fatalf("CreateExperiment(%s) failed: %v", name, err)
		}
	}

	experiments, err := s.ListExperiments(ctx)
	if err != nil {
		t.Fatalf("ListExperiments() failed: %v", err)
	}
	if len(experiments) != 3 {
		t.Errorf("ListExperiments() returned %d experiments, want 3", len(experiments))
	}
}

func TestListExperimentsEmptyReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	experiments, err := s.ListExperiments(ctx)
	if err != nil {
		t.Fatalf("ListExperiments() failed: %v", err)
	}
	if experiments == nil {
		t.Error("ListExperiments() returned nil, want empty slice")
	}
	if len(experiments) != 0 {
		t.Errorf("ListExperiments() returned %d experiments, want 0", len(experiments))
	}
}

func TestDeleteExperiment(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	id, err := s.CreateExperiment(ctx, &Experiment{Name: "to-delete", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	err = s.DeleteExperiment(ctx, id)
	if err != nil {
		t.Fatalf("DeleteExperiment() failed: %v", err)
	}

	_, err = s.GetExperiment(ctx, id)
	if err != ErrNotFound {
		t.Errorf("GetExperiment() after delete: error = %v, want ErrNotFound", err)
	}
}

func TestDeleteExperimentNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	err := s.DeleteExperiment(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("DeleteExperiment() error = %v, want ErrNotFound", err)
	}
}

func TestDeleteExperimentCascadesToJunctionTables(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Create experiment
	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "cascade-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	// Create scanner and project
	scannerID, err := s.CreateScanner(ctx, &Scanner{
		Name:        "cascade-scanner",
		Version:     "1.0.0",
		DockerImage: "test:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}

	projectID, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "cascade-project",
		LocalPath: "/tmp/cascade",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	// Link scanner and project to experiment
	if err := s.AddScannerToExperiment(ctx, expID, scannerID); err != nil {
		t.Fatalf("AddScannerToExperiment() failed: %v", err)
	}
	if err := s.AddProjectToExperiment(ctx, expID, projectID); err != nil {
		t.Fatalf("AddProjectToExperiment() failed: %v", err)
	}

	// Verify links exist
	scanners, err := s.ListExperimentScanners(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentScanners() failed: %v", err)
	}
	if len(scanners) != 1 {
		t.Errorf("Expected 1 scanner linked, got %d", len(scanners))
	}

	projects, err := s.ListExperimentProjects(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentProjects() failed: %v", err)
	}
	if len(projects) != 1 {
		t.Errorf("Expected 1 project linked, got %d", len(projects))
	}

	// Delete experiment
	if err := s.DeleteExperiment(ctx, expID); err != nil {
		t.Fatalf("DeleteExperiment() failed: %v", err)
	}

	// Verify links are cascade deleted (querying with non-existent experiment should return empty)
	scanners, err = s.ListExperimentScanners(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentScanners() after delete failed: %v", err)
	}
	if len(scanners) != 0 {
		t.Errorf("Expected 0 scanners after cascade delete, got %d", len(scanners))
	}

	projects, err = s.ListExperimentProjects(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentProjects() after delete failed: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("Expected 0 projects after cascade delete, got %d", len(projects))
	}

	// Scanner and project should still exist (not cascade deleted from their own tables)
	_, err = s.GetScanner(ctx, scannerID)
	if err != nil {
		t.Errorf("Scanner should still exist after experiment delete: %v", err)
	}
	_, err = s.GetProject(ctx, projectID)
	if err != nil {
		t.Errorf("Project should still exist after experiment delete: %v", err)
	}
}

func TestAddScannerToExperiment(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "scanner-link-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	scannerID, err := s.CreateScanner(ctx, &Scanner{
		Name:        "link-scanner",
		Version:     "1.0.0",
		DockerImage: "test:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}

	err = s.AddScannerToExperiment(ctx, expID, scannerID)
	if err != nil {
		t.Fatalf("AddScannerToExperiment() failed: %v", err)
	}

	scanners, err := s.ListExperimentScanners(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentScanners() failed: %v", err)
	}
	if len(scanners) != 1 {
		t.Errorf("Expected 1 scanner, got %d", len(scanners))
	}
	if scanners[0].ID != scannerID {
		t.Errorf("Scanner ID = %d, want %d", scanners[0].ID, scannerID)
	}
}

func TestAddProjectToExperiment(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "project-link-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	projectID, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "link-project",
		LocalPath: "/tmp/link",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	err = s.AddProjectToExperiment(ctx, expID, projectID)
	if err != nil {
		t.Fatalf("AddProjectToExperiment() failed: %v", err)
	}

	projects, err := s.ListExperimentProjects(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentProjects() failed: %v", err)
	}
	if len(projects) != 1 {
		t.Errorf("Expected 1 project, got %d", len(projects))
	}
	if projects[0].ID != projectID {
		t.Errorf("Project ID = %d, want %d", projects[0].ID, projectID)
	}
}

func TestListExperimentScanners(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "multi-scanner-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	// Create and link multiple scanners
	for _, name := range []string{"scanner-a", "scanner-b", "scanner-c"} {
		scannerID, err := s.CreateScanner(ctx, &Scanner{
			Name:        name,
			Version:     "1.0.0",
			DockerImage: "test-" + name + ":1.0.0",
		})
		if err != nil {
			t.Fatalf("CreateScanner(%s) failed: %v", name, err)
		}
		if err := s.AddScannerToExperiment(ctx, expID, scannerID); err != nil {
			t.Fatalf("AddScannerToExperiment(%s) failed: %v", name, err)
		}
	}

	scanners, err := s.ListExperimentScanners(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentScanners() failed: %v", err)
	}
	if len(scanners) != 3 {
		t.Errorf("Expected 3 scanners, got %d", len(scanners))
	}

	// Verify sorted by name
	if scanners[0].Name != "scanner-a" || scanners[1].Name != "scanner-b" || scanners[2].Name != "scanner-c" {
		t.Errorf("ListExperimentScanners() not sorted by name: %v", scanners)
	}
}

func TestListExperimentProjects(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "multi-project-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	// Create and link multiple projects
	for _, name := range []string{"project-a", "project-b", "project-c"} {
		projectID, err := s.CreateProject(ctx, &CorpusProject{
			Name:      name,
			LocalPath: "/tmp/" + name,
		})
		if err != nil {
			t.Fatalf("CreateProject(%s) failed: %v", name, err)
		}
		if err := s.AddProjectToExperiment(ctx, expID, projectID); err != nil {
			t.Fatalf("AddProjectToExperiment(%s) failed: %v", name, err)
		}
	}

	projects, err := s.ListExperimentProjects(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentProjects() failed: %v", err)
	}
	if len(projects) != 3 {
		t.Errorf("Expected 3 projects, got %d", len(projects))
	}

	// Verify sorted by name
	if projects[0].Name != "project-a" || projects[1].Name != "project-b" || projects[2].Name != "project-c" {
		t.Errorf("ListExperimentProjects() not sorted by name: %v", projects)
	}
}

func TestDuplicateScannerExperimentLinkIsIdempotent(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "dup-scanner-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	scannerID, err := s.CreateScanner(ctx, &Scanner{
		Name:        "dup-scanner",
		Version:     "1.0.0",
		DockerImage: "test:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}

	// First link
	err = s.AddScannerToExperiment(ctx, expID, scannerID)
	if err != nil {
		t.Fatalf("first AddScannerToExperiment() failed: %v", err)
	}

	// Duplicate link should succeed (idempotent)
	err = s.AddScannerToExperiment(ctx, expID, scannerID)
	if err != nil {
		t.Errorf("second AddScannerToExperiment() should succeed but got: %v", err)
	}

	// Should still have only 1 scanner linked
	scanners, err := s.ListExperimentScanners(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentScanners() failed: %v", err)
	}
	if len(scanners) != 1 {
		t.Errorf("Expected 1 scanner after duplicate add, got %d", len(scanners))
	}
}

func TestDuplicateProjectExperimentLinkIsIdempotent(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "dup-project-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	projectID, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "dup-project",
		LocalPath: "/tmp/dup",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	// First link
	err = s.AddProjectToExperiment(ctx, expID, projectID)
	if err != nil {
		t.Fatalf("first AddProjectToExperiment() failed: %v", err)
	}

	// Duplicate link should succeed (idempotent)
	err = s.AddProjectToExperiment(ctx, expID, projectID)
	if err != nil {
		t.Errorf("second AddProjectToExperiment() should succeed but got: %v", err)
	}

	// Should still have only 1 project linked
	projects, err := s.ListExperimentProjects(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentProjects() failed: %v", err)
	}
	if len(projects) != 1 {
		t.Errorf("Expected 1 project after duplicate add, got %d", len(projects))
	}
}

func TestListExperimentScannersWithNoScannersReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "empty-scanners-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	scanners, err := s.ListExperimentScanners(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentScanners() failed: %v", err)
	}
	if scanners == nil {
		t.Error("ListExperimentScanners() returned nil, want empty slice")
	}
	if len(scanners) != 0 {
		t.Errorf("ListExperimentScanners() returned %d scanners, want 0", len(scanners))
	}
}

func TestListExperimentProjectsWithNoProjectsReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "empty-projects-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	projects, err := s.ListExperimentProjects(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentProjects() failed: %v", err)
	}
	if projects == nil {
		t.Error("ListExperimentProjects() returned nil, want empty slice")
	}
	if len(projects) != 0 {
		t.Errorf("ListExperimentProjects() returned %d projects, want 0", len(projects))
	}
}

func TestRemoveScannerFromExperiment(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "remove-scanner-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	scannerID, err := s.CreateScanner(ctx, &Scanner{
		Name:        "remove-scanner",
		Version:     "1.0.0",
		DockerImage: "test:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}

	if err := s.AddScannerToExperiment(ctx, expID, scannerID); err != nil {
		t.Fatalf("AddScannerToExperiment() failed: %v", err)
	}

	err = s.RemoveScannerFromExperiment(ctx, expID, scannerID)
	if err != nil {
		t.Fatalf("RemoveScannerFromExperiment() failed: %v", err)
	}

	scanners, err := s.ListExperimentScanners(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentScanners() failed: %v", err)
	}
	if len(scanners) != 0 {
		t.Errorf("Expected 0 scanners after remove, got %d", len(scanners))
	}
}

func TestRemoveScannerFromExperimentNotLinked(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "remove-unlinked-scanner", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	scannerID, err := s.CreateScanner(ctx, &Scanner{
		Name:        "unlinked-scanner",
		Version:     "1.0.0",
		DockerImage: "test:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}

	// Try to remove without linking first
	err = s.RemoveScannerFromExperiment(ctx, expID, scannerID)
	if err != ErrNotFound {
		t.Errorf("RemoveScannerFromExperiment() error = %v, want ErrNotFound", err)
	}
}

func TestRemoveProjectFromExperiment(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "remove-project-test", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	projectID, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "remove-project",
		LocalPath: "/tmp/remove",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	if err := s.AddProjectToExperiment(ctx, expID, projectID); err != nil {
		t.Fatalf("AddProjectToExperiment() failed: %v", err)
	}

	err = s.RemoveProjectFromExperiment(ctx, expID, projectID)
	if err != nil {
		t.Fatalf("RemoveProjectFromExperiment() failed: %v", err)
	}

	projects, err := s.ListExperimentProjects(ctx, expID)
	if err != nil {
		t.Fatalf("ListExperimentProjects() failed: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("Expected 0 projects after remove, got %d", len(projects))
	}
}

func TestRemoveProjectFromExperimentNotLinked(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID, err := s.CreateExperiment(ctx, &Experiment{Name: "remove-unlinked-project", Iterations: 1})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	projectID, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "unlinked-project",
		LocalPath: "/tmp/unlinked",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	// Try to remove without linking first
	err = s.RemoveProjectFromExperiment(ctx, expID, projectID)
	if err != ErrNotFound {
		t.Errorf("RemoveProjectFromExperiment() error = %v, want ErrNotFound", err)
	}
}

func TestGetExperimentByName(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Not found case
	_, err := s.GetExperimentByName(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Fatalf("GetExperimentByName() error = %v, want ErrNotFound", err)
	}

	// Create and retrieve
	id, err := s.CreateExperiment(ctx, &Experiment{
		Name:        "my-experiment",
		Description: sql.NullString{String: "desc", Valid: true},
		Iterations:  2,
	})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}

	got, err := s.GetExperimentByName(ctx, "my-experiment")
	if err != nil {
		t.Fatalf("GetExperimentByName() failed: %v", err)
	}
	if got.ID != id {
		t.Errorf("ID = %d, want %d", got.ID, id)
	}
	if got.Name != "my-experiment" {
		t.Errorf("Name = %q, want %q", got.Name, "my-experiment")
	}
	if got.Iterations != 2 {
		t.Errorf("Iterations = %d, want 2", got.Iterations)
	}
}
