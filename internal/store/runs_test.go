package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestCreateGetRunRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Create prerequisite entities
	expID := createTestExperimentForRuns(t, s)
	scannerID := createTestScannerForRuns(t, s)
	projectID := createTestProjectForRuns(t, s)

	r := &Run{
		ExperimentID: expID,
		ScannerID:    scannerID,
		ProjectID:    projectID,
		Iteration:    1,
		Status:       RunStatusPending,
	}

	id, err := s.CreateRun(ctx, r)
	if err != nil {
		t.Fatalf("CreateRun() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	got, err := s.GetRun(ctx, id)
	if err != nil {
		t.Fatalf("GetRun() failed: %v", err)
	}
	if got.ExperimentID != r.ExperimentID {
		t.Errorf("ExperimentID = %d, want %d", got.ExperimentID, r.ExperimentID)
	}
	if got.ScannerID != r.ScannerID {
		t.Errorf("ScannerID = %d, want %d", got.ScannerID, r.ScannerID)
	}
	if got.ProjectID != r.ProjectID {
		t.Errorf("ProjectID = %d, want %d", got.ProjectID, r.ProjectID)
	}
	if got.Iteration != r.Iteration {
		t.Errorf("Iteration = %d, want %d", got.Iteration, r.Iteration)
	}
	if got.Status != r.Status {
		t.Errorf("Status = %q, want %q", got.Status, r.Status)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestListRunsByExperiment(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID := createTestExperimentForRuns(t, s)
	scannerID := createTestScannerForRuns(t, s)
	projectID := createTestProjectForRuns(t, s)

	// Create multiple runs
	for i := 1; i <= 3; i++ {
		_, err := s.CreateRun(ctx, &Run{
			ExperimentID: expID,
			ScannerID:    scannerID,
			ProjectID:    projectID,
			Iteration:    i,
			Status:       RunStatusPending,
		})
		if err != nil {
			t.Fatalf("CreateRun() failed: %v", err)
		}
	}

	runs, err := s.ListRunsByExperiment(ctx, expID)
	if err != nil {
		t.Fatalf("ListRunsByExperiment() failed: %v", err)
	}
	if len(runs) != 3 {
		t.Errorf("ListRunsByExperiment() returned %d runs, want 3", len(runs))
	}
}

func TestUpdateRunStatus(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID := createTestExperimentForRuns(t, s)
	scannerID := createTestScannerForRuns(t, s)
	projectID := createTestProjectForRuns(t, s)

	id, err := s.CreateRun(ctx, &Run{
		ExperimentID: expID,
		ScannerID:    scannerID,
		ProjectID:    projectID,
		Iteration:    1,
		Status:       RunStatusPending,
	})
	if err != nil {
		t.Fatalf("CreateRun() failed: %v", err)
	}

	now := time.Now()
	startedAt := sql.NullTime{Time: now, Valid: true}
	completedAt := sql.NullTime{Time: now.Add(10 * time.Second), Valid: true}
	durationMs := sql.NullInt64{Int64: 10000, Valid: true}
	memoryPeakBytes := sql.NullInt64{Int64: 1024 * 1024, Valid: true}
	sarifPath := sql.NullString{String: "/tmp/results.sarif", Valid: true}
	errorMessage := sql.NullString{}

	err = s.UpdateRunStatus(ctx, id, RunStatusCompleted, startedAt, completedAt, durationMs, memoryPeakBytes, sarifPath, sql.NullString{}, errorMessage)
	if err != nil {
		t.Fatalf("UpdateRunStatus() failed: %v", err)
	}

	got, err := s.GetRun(ctx, id)
	if err != nil {
		t.Fatalf("GetRun() failed: %v", err)
	}
	if got.Status != RunStatusCompleted {
		t.Errorf("Status = %q, want %q", got.Status, RunStatusCompleted)
	}
	if !got.StartedAt.Valid {
		t.Error("StartedAt should be set")
	}
	if !got.CompletedAt.Valid {
		t.Error("CompletedAt should be set")
	}
	if got.DurationMs.Int64 != 10000 {
		t.Errorf("DurationMs = %d, want 10000", got.DurationMs.Int64)
	}
	if got.SarifPath.String != "/tmp/results.sarif" {
		t.Errorf("SarifPath = %q, want /tmp/results.sarif", got.SarifPath.String)
	}
}

func TestListPendingRuns(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID := createTestExperimentForRuns(t, s)
	scannerID := createTestScannerForRuns(t, s)
	projectID := createTestProjectForRuns(t, s)

	// Create runs with different statuses
	statuses := []RunStatus{RunStatusPending, RunStatusRunning, RunStatusCompleted, RunStatusFailed}
	for i, status := range statuses {
		_, err := s.CreateRun(ctx, &Run{
			ExperimentID: expID,
			ScannerID:    scannerID,
			ProjectID:    projectID,
			Iteration:    i + 1,
			Status:       status,
		})
		if err != nil {
			t.Fatalf("CreateRun() failed: %v", err)
		}
	}

	pendingRuns, err := s.ListPendingRuns(ctx, expID)
	if err != nil {
		t.Fatalf("ListPendingRuns() failed: %v", err)
	}
	// Should return pending and failed runs only
	if len(pendingRuns) != 2 {
		t.Errorf("ListPendingRuns() returned %d runs, want 2", len(pendingRuns))
	}

	for _, r := range pendingRuns {
		if r.Status != RunStatusPending && r.Status != RunStatusFailed {
			t.Errorf("ListPendingRuns() returned run with status %q", r.Status)
		}
	}
}

func TestGetRunNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.GetRun(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("GetRun() error = %v, want ErrNotFound", err)
	}
}

func TestListRunsByExperimentEmptyReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	expID := createTestExperimentForRuns(t, s)

	runs, err := s.ListRunsByExperiment(ctx, expID)
	if err != nil {
		t.Fatalf("ListRunsByExperiment() failed: %v", err)
	}
	if runs == nil {
		t.Error("ListRunsByExperiment() returned nil, want empty slice")
	}
	if len(runs) != 0 {
		t.Errorf("ListRunsByExperiment() returned %d runs, want 0", len(runs))
	}
}

func TestUpdateRunStatusNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	err := s.UpdateRunStatus(ctx, 9999, RunStatusCompleted, sql.NullTime{}, sql.NullTime{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, sql.NullString{})
	if err != ErrNotFound {
		t.Errorf("UpdateRunStatus() error = %v, want ErrNotFound", err)
	}
}

func TestDeleteRun(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	expID := createTestExperimentForRuns(t, s)
	scannerID := createTestScannerForRuns(t, s)
	projectID := createTestProjectForRuns(t, s)

	id, err := s.CreateRun(ctx, &Run{
		ExperimentID: expID,
		ScannerID:    scannerID,
		ProjectID:    projectID,
		Iteration:    1,
		Status:       RunStatusPending,
	})
	if err != nil {
		t.Fatalf("CreateRun() failed: %v", err)
	}

	err = s.DeleteRun(ctx, id)
	if err != nil {
		t.Fatalf("DeleteRun() failed: %v", err)
	}

	_, err = s.GetRun(ctx, id)
	if err != ErrNotFound {
		t.Errorf("GetRun() after delete: error = %v, want ErrNotFound", err)
	}
}

func TestListRunsByProject_FiltersAndOrders(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()

	expID := createTestExperimentForRuns(t, s)
	scannerID := createTestScannerForRuns(t, s)
	projectA := createTestProjectForRuns(t, s)
	projectB := createTestProjectForRuns(t, s)

	// Two runs on A, one on B. ListRunsByProject(A) must return exactly
	// the two A runs, ordered by ID.
	a1, _ := s.CreateRun(ctx, &Run{ExperimentID: expID, ScannerID: scannerID, ProjectID: projectA, Iteration: 1, Status: RunStatusCompleted})
	s.CreateRun(ctx, &Run{ExperimentID: expID, ScannerID: scannerID, ProjectID: projectB, Iteration: 1, Status: RunStatusCompleted})
	a2, _ := s.CreateRun(ctx, &Run{ExperimentID: expID, ScannerID: scannerID, ProjectID: projectA, Iteration: 2, Status: RunStatusFailed})

	got, err := s.ListRunsByProject(ctx, projectA)
	if err != nil {
		t.Fatalf("ListRunsByProject() failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d runs, want 2", len(got))
	}
	if got[0].ID != a1 || got[1].ID != a2 {
		t.Errorf("got run IDs [%d %d], want [%d %d] (ordered by id)", got[0].ID, got[1].ID, a1, a2)
	}
	if got[0].ProjectID != projectA || got[1].ProjectID != projectA {
		t.Error("returned runs for wrong project")
	}
}

func TestListRunsByProject_EmptyNotNil(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	projectID := createTestProjectForRuns(t, s)
	got, err := s.ListRunsByProject(context.Background(), projectID)
	if err != nil {
		t.Fatalf("ListRunsByProject() failed: %v", err)
	}
	if got == nil {
		t.Error("got nil, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("got %d runs, want 0", len(got))
	}
}

// Helper functions - unique names to avoid redeclaration
var runsTestCounter int

func createTestExperimentForRuns(t *testing.T, s *Store) int64 {
	t.Helper()
	runsTestCounter++
	ctx := context.Background()
	id, err := s.CreateExperiment(ctx, &Experiment{
		Name:       "test-experiment-runs-" + string(rune('a'+runsTestCounter)),
		Iterations: 1,
	})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}
	return id
}

func createTestScannerForRuns(t *testing.T, s *Store) int64 {
	t.Helper()
	runsTestCounter++
	ctx := context.Background()
	id, err := s.CreateScanner(ctx, &Scanner{
		Name:        "test-scanner-runs-" + string(rune('a'+runsTestCounter)),
		Version:     "1.0.0",
		DockerImage: "test-scanner:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}
	return id
}

func createTestProjectForRuns(t *testing.T, s *Store) int64 {
	t.Helper()
	runsTestCounter++
	ctx := context.Background()
	id, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "test-project-runs-" + string(rune('a'+runsTestCounter)),
		LocalPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}
	return id
}
