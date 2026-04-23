package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

var dispositionsTestCounter int

func dispositionsCreateTestRun(t *testing.T, s *Store) int64 {
	t.Helper()
	ctx := context.Background()
	expID := dispositionsCreateTestExperiment(t, s)
	scannerID := dispositionsCreateTestScanner(t, s)
	projectID := dispositionsCreateTestProject(t, s)

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
	return id
}

func dispositionsCreateTestExperiment(t *testing.T, s *Store) int64 {
	t.Helper()
	dispositionsTestCounter++
	ctx := context.Background()
	id, err := s.CreateExperiment(ctx, &Experiment{
		Name:       fmt.Sprintf("test-experiment-dispositions-%d", dispositionsTestCounter),
		Iterations: 1,
	})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}
	return id
}

func dispositionsCreateTestScanner(t *testing.T, s *Store) int64 {
	t.Helper()
	dispositionsTestCounter++
	ctx := context.Background()
	id, err := s.CreateScanner(ctx, &Scanner{
		Name:        fmt.Sprintf("test-scanner-dispositions-%d", dispositionsTestCounter),
		Version:     "1.0.0",
		DockerImage: "test-scanner:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}
	return id
}

func dispositionsCreateTestProject(t *testing.T, s *Store) int64 {
	t.Helper()
	dispositionsTestCounter++
	ctx := context.Background()
	id, err := s.CreateProject(ctx, &CorpusProject{
		Name:      fmt.Sprintf("test-project-dispositions-%d", dispositionsTestCounter),
		LocalPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}
	return id
}

func dispositionsCreateTestFinding(t *testing.T, s *Store, runID int64) int64 {
	t.Helper()
	dispositionsTestCounter++
	ctx := context.Background()
	id, err := s.CreateFinding(ctx, &Finding{
		RunID:     runID,
		FilePath:  fmt.Sprintf("file-dispositions-%d.go", dispositionsTestCounter),
		StartLine: 10,
	})
	if err != nil {
		t.Fatalf("CreateFinding() failed: %v", err)
	}
	return id
}

func TestCreateDispositionGetDispositionRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)
	findingID := dispositionsCreateTestFinding(t, s, runID)

	d := &FindingDisposition{
		FindingID:   findingID,
		Disposition: "fp",
		Notes:       sql.NullString{String: "false positive from test helper", Valid: true},
		ReviewedBy:  sql.NullString{String: "tester", Valid: true},
	}

	id, err := s.CreateDisposition(ctx, d)
	if err != nil {
		t.Fatalf("CreateDisposition() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	got, err := s.GetDisposition(ctx, id)
	if err != nil {
		t.Fatalf("GetDisposition() failed: %v", err)
	}

	if got.FindingID != findingID {
		t.Errorf("FindingID = %d, want %d", got.FindingID, findingID)
	}
	if got.Disposition != "fp" {
		t.Errorf("Disposition = %q, want %q", got.Disposition, "fp")
	}
	if got.Notes.String != "false positive from test helper" {
		t.Errorf("Notes = %q, want %q", got.Notes.String, "false positive from test helper")
	}
	if got.ReviewedBy.String != "tester" {
		t.Errorf("ReviewedBy = %q, want %q", got.ReviewedBy.String, "tester")
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestGetDispositionByFinding(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)
	findingID := dispositionsCreateTestFinding(t, s, runID)

	d := &FindingDisposition{
		FindingID:   findingID,
		Disposition: "tp",
	}

	_, err := s.CreateDisposition(ctx, d)
	if err != nil {
		t.Fatalf("CreateDisposition() failed: %v", err)
	}

	got, err := s.GetDispositionByFinding(ctx, findingID)
	if err != nil {
		t.Fatalf("GetDispositionByFinding() failed: %v", err)
	}

	if got.FindingID != findingID {
		t.Errorf("FindingID = %d, want %d", got.FindingID, findingID)
	}
	if got.Disposition != "tp" {
		t.Errorf("Disposition = %q, want %q", got.Disposition, "tp")
	}
}

func TestListDispositionsByRun(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)
	findingID1 := dispositionsCreateTestFinding(t, s, runID)
	findingID2 := dispositionsCreateTestFinding(t, s, runID)

	_, err := s.CreateDisposition(ctx, &FindingDisposition{
		FindingID:   findingID1,
		Disposition: "tp",
	})
	if err != nil {
		t.Fatalf("CreateDisposition() 1 failed: %v", err)
	}

	_, err = s.CreateDisposition(ctx, &FindingDisposition{
		FindingID:   findingID2,
		Disposition: "fp",
	})
	if err != nil {
		t.Fatalf("CreateDisposition() 2 failed: %v", err)
	}

	dispositions, err := s.ListDispositionsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListDispositionsByRun() failed: %v", err)
	}
	if len(dispositions) != 2 {
		t.Fatalf("ListDispositionsByRun() returned %d dispositions, want 2", len(dispositions))
	}

	// Verify ordering by finding_id
	if dispositions[0].FindingID > dispositions[1].FindingID {
		t.Errorf("expected dispositions ordered by finding_id, got %d then %d",
			dispositions[0].FindingID, dispositions[1].FindingID)
	}
}

func TestListDispositionsByRunEmptyReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)

	dispositions, err := s.ListDispositionsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListDispositionsByRun() failed: %v", err)
	}
	if dispositions == nil {
		t.Error("ListDispositionsByRun() returned nil, want empty slice")
	}
	if len(dispositions) != 0 {
		t.Errorf("ListDispositionsByRun() returned %d dispositions, want 0", len(dispositions))
	}
}

func TestCreateDispositionUpsert(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)
	findingID := dispositionsCreateTestFinding(t, s, runID)

	// First insert
	_, err := s.CreateDisposition(ctx, &FindingDisposition{
		FindingID:   findingID,
		Disposition: "needs_review",
		Notes:       sql.NullString{String: "initial review", Valid: true},
	})
	if err != nil {
		t.Fatalf("first CreateDisposition() failed: %v", err)
	}

	// Upsert with updated disposition
	_, err = s.CreateDisposition(ctx, &FindingDisposition{
		FindingID:   findingID,
		Disposition: "fp",
		Notes:       sql.NullString{String: "confirmed false positive", Valid: true},
		ReviewedBy:  sql.NullString{String: "reviewer2", Valid: true},
	})
	if err != nil {
		t.Fatalf("upsert CreateDisposition() failed: %v", err)
	}

	got, err := s.GetDispositionByFinding(ctx, findingID)
	if err != nil {
		t.Fatalf("GetDispositionByFinding() failed: %v", err)
	}

	if got.Disposition != "fp" {
		t.Errorf("Disposition = %q, want %q", got.Disposition, "fp")
	}
	if got.Notes.String != "confirmed false positive" {
		t.Errorf("Notes = %q, want %q", got.Notes.String, "confirmed false positive")
	}
	if got.ReviewedBy.String != "reviewer2" {
		t.Errorf("ReviewedBy = %q, want %q", got.ReviewedBy.String, "reviewer2")
	}

	// Should still be only one disposition for this finding
	dispositions, err := s.ListDispositionsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListDispositionsByRun() failed: %v", err)
	}
	if len(dispositions) != 1 {
		t.Errorf("expected 1 disposition after upsert, got %d", len(dispositions))
	}
}

func TestCreateDispositionInvalidDisposition(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)
	findingID := dispositionsCreateTestFinding(t, s, runID)

	_, err := s.CreateDisposition(ctx, &FindingDisposition{
		FindingID:   findingID,
		Disposition: "invalid_value",
	})
	if err == nil {
		t.Error("CreateDisposition() with invalid disposition should fail")
	}
}

func TestDeleteDisposition(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)
	findingID := dispositionsCreateTestFinding(t, s, runID)

	id, err := s.CreateDisposition(ctx, &FindingDisposition{
		FindingID:   findingID,
		Disposition: "tp",
	})
	if err != nil {
		t.Fatalf("CreateDisposition() failed: %v", err)
	}

	err = s.DeleteDisposition(ctx, id)
	if err != nil {
		t.Fatalf("DeleteDisposition() failed: %v", err)
	}

	_, err = s.GetDisposition(ctx, id)
	if err != ErrNotFound {
		t.Errorf("GetDisposition() after delete: got err=%v, want ErrNotFound", err)
	}
}

func TestDeleteDispositionNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	err := s.DeleteDisposition(ctx, 99999)
	if err != ErrNotFound {
		t.Errorf("DeleteDisposition() non-existent: got err=%v, want ErrNotFound", err)
	}
}

func TestDeleteFindingCascadesToDisposition(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := dispositionsCreateTestRun(t, s)
	findingID := dispositionsCreateTestFinding(t, s, runID)

	id, err := s.CreateDisposition(ctx, &FindingDisposition{
		FindingID:   findingID,
		Disposition: "fp",
	})
	if err != nil {
		t.Fatalf("CreateDisposition() failed: %v", err)
	}

	// Delete the finding
	err = s.DeleteFinding(ctx, findingID)
	if err != nil {
		t.Fatalf("DeleteFinding() failed: %v", err)
	}

	// Disposition should be cascade deleted
	_, err = s.GetDisposition(ctx, id)
	if err != ErrNotFound {
		t.Errorf("GetDisposition() after finding delete: got err=%v, want ErrNotFound", err)
	}
}
