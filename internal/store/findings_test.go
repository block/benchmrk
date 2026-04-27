package store

import (
	"context"
	"database/sql"
	"testing"
)

func TestCreateFindingListFindingsByRunRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)

	f := &Finding{
		RunID:       runID,
		RuleID:      sql.NullString{String: "sql-injection-001", Valid: true},
		FilePath:    "src/main.go",
		StartLine:   42,
		EndLine:     sql.NullInt64{Int64: 45, Valid: true},
		CWEID:       sql.NullString{String: "CWE-89", Valid: true},
		Severity:    sql.NullString{String: "high", Valid: true},
		Message:     sql.NullString{String: "SQL injection vulnerability", Valid: true},
		Snippet:     sql.NullString{String: "db.Query(userInput)", Valid: true},
		Fingerprint: sql.NullString{String: "abc123", Valid: true},
	}

	id, err := s.CreateFinding(ctx, f)
	if err != nil {
		t.Fatalf("CreateFinding() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	findings, err := s.ListFindingsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListFindingsByRun() failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ListFindingsByRun() returned %d findings, want 1", len(findings))
	}

	got := findings[0]
	if got.RuleID != f.RuleID {
		t.Errorf("RuleID = %v, want %v", got.RuleID, f.RuleID)
	}
	if got.FilePath != f.FilePath {
		t.Errorf("FilePath = %q, want %q", got.FilePath, f.FilePath)
	}
	if got.StartLine != f.StartLine {
		t.Errorf("StartLine = %d, want %d", got.StartLine, f.StartLine)
	}
	if got.CWEID != f.CWEID {
		t.Errorf("CWEID = %v, want %v", got.CWEID, f.CWEID)
	}
}

func TestBulkCreateFindings(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)

	findings := []Finding{
		{RunID: runID, FilePath: "a.go", StartLine: 10},
		{RunID: runID, FilePath: "b.go", StartLine: 20},
		{RunID: runID, FilePath: "c.go", StartLine: 30},
	}

	err := s.BulkCreateFindings(ctx, findings)
	if err != nil {
		t.Fatalf("BulkCreateFindings() failed: %v", err)
	}

	got, err := s.ListFindingsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListFindingsByRun() failed: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("ListFindingsByRun() returned %d findings, want 3", len(got))
	}
}

func TestBulkCreateFindingsEmpty(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	err := s.BulkCreateFindings(ctx, []Finding{})
	if err != nil {
		t.Fatalf("BulkCreateFindings() with empty slice failed: %v", err)
	}
}

func TestBulkCreateFindingsRollbackOnError(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)

	// Second finding has invalid run_id (FK violation)
	findings := []Finding{
		{RunID: runID, FilePath: "a.go", StartLine: 10},
		{RunID: 99999, FilePath: "b.go", StartLine: 20}, // Invalid FK
	}

	err := s.BulkCreateFindings(ctx, findings)
	if err == nil {
		t.Fatal("BulkCreateFindings() with FK violation should fail")
	}

	// Verify rollback: no findings should exist
	got, err := s.ListFindingsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListFindingsByRun() failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Expected 0 findings after rollback, got %d", len(got))
	}
}

func TestCreateFindingMatchLinksToAnnotation(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)
	findingID, _ := s.CreateFinding(ctx, &Finding{RunID: runID, FilePath: "a.go", StartLine: 10})

	// Need a project for annotation
	projectID := createTestProjectForFindings(t, s)
	annotationID := createTestAnnotationForFindings(t, s, projectID)

	m := &FindingMatch{
		FindingID:    findingID,
		AnnotationID: annotationID,
		MatchType:    "exact",
		Confidence:   sql.NullFloat64{Float64: 1.0, Valid: true},
	}

	id, err := s.CreateFindingMatch(ctx, m)
	if err != nil {
		t.Fatalf("CreateFindingMatch() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	matches, err := s.ListFindingMatchesByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListFindingMatchesByRun() failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("ListFindingMatchesByRun() returned %d matches, want 1", len(matches))
	}

	got := matches[0]
	if got.FindingID != findingID {
		t.Errorf("FindingID = %d, want %d", got.FindingID, findingID)
	}
	if got.AnnotationID != annotationID {
		t.Errorf("AnnotationID = %d, want %d", got.AnnotationID, annotationID)
	}
	if got.MatchType != "exact" {
		t.Errorf("MatchType = %q, want exact", got.MatchType)
	}
}

func TestDuplicateFindingAnnotationMatchFails(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)
	findingID, _ := s.CreateFinding(ctx, &Finding{RunID: runID, FilePath: "a.go", StartLine: 10})
	projectID := createTestProjectForFindings(t, s)
	annotationID := createTestAnnotationForFindings(t, s, projectID)

	m := &FindingMatch{
		FindingID:    findingID,
		AnnotationID: annotationID,
		MatchType:    "exact",
	}

	_, err := s.CreateFindingMatch(ctx, m)
	if err != nil {
		t.Fatalf("first CreateFindingMatch() failed: %v", err)
	}

	_, err = s.CreateFindingMatch(ctx, m)
	if err == nil {
		t.Error("duplicate CreateFindingMatch() should fail")
	}
}

func TestListUnmatchedFindingsReturnsFindingsWithNoMatch(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)
	projectID := createTestProjectForFindings(t, s)
	annotationID := createTestAnnotationForFindings(t, s, projectID)

	// Create two findings
	matchedFindingID, _ := s.CreateFinding(ctx, &Finding{RunID: runID, FilePath: "matched.go", StartLine: 10})
	_, _ = s.CreateFinding(ctx, &Finding{RunID: runID, FilePath: "unmatched.go", StartLine: 20})

	// Match only the first finding
	_, _ = s.CreateFindingMatch(ctx, &FindingMatch{
		FindingID:    matchedFindingID,
		AnnotationID: annotationID,
		MatchType:    "exact",
	})

	unmatched, err := s.ListUnmatchedFindings(ctx, runID)
	if err != nil {
		t.Fatalf("ListUnmatchedFindings() failed: %v", err)
	}
	if len(unmatched) != 1 {
		t.Fatalf("ListUnmatchedFindings() returned %d findings, want 1", len(unmatched))
	}
	if unmatched[0].FilePath != "unmatched.go" {
		t.Errorf("unmatched finding FilePath = %q, want unmatched.go", unmatched[0].FilePath)
	}
}

func TestListUnmatchedAnnotationsReturnsAnnotationsWithNoMatch(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)
	projectID := createTestProjectForFindings(t, s)

	// Create two annotations
	matchedAnnotationID := createTestAnnotationWithFileForFindings(t, s, projectID, "matched.go")
	_ = createTestAnnotationWithFileForFindings(t, s, projectID, "unmatched.go")

	// Create a finding and match it to only the first annotation
	findingID, _ := s.CreateFinding(ctx, &Finding{RunID: runID, FilePath: "a.go", StartLine: 10})
	_, _ = s.CreateFindingMatch(ctx, &FindingMatch{
		FindingID:    findingID,
		AnnotationID: matchedAnnotationID,
		MatchType:    "exact",
	})

	unmatched, err := s.ListUnmatchedAnnotations(ctx, runID, projectID)
	if err != nil {
		t.Fatalf("ListUnmatchedAnnotations() failed: %v", err)
	}
	if len(unmatched) != 1 {
		t.Fatalf("ListUnmatchedAnnotations() returned %d annotations, want 1", len(unmatched))
	}
	if unmatched[0].FilePath != "unmatched.go" {
		t.Errorf("unmatched annotation FilePath = %q, want unmatched.go", unmatched[0].FilePath)
	}
}

func TestListFindingsByRunEmptyReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	runID := createTestRunForFindings(t, s)

	findings, err := s.ListFindingsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListFindingsByRun() failed: %v", err)
	}
	if findings == nil {
		t.Error("ListFindingsByRun() returned nil, want empty slice")
	}
	if len(findings) != 0 {
		t.Errorf("ListFindingsByRun() returned %d findings, want 0", len(findings))
	}
}

func TestDeleteRunCascadesToFindings(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	runID := createTestRunForFindings(t, s)
	findingID, _ := s.CreateFinding(ctx, &Finding{RunID: runID, FilePath: "a.go", StartLine: 10})

	// Delete the run
	err := s.DeleteRun(ctx, runID)
	if err != nil {
		t.Fatalf("DeleteRun() failed: %v", err)
	}

	// Verify finding is cascade deleted
	findings, err := s.ListFindingsByRun(ctx, runID)
	if err != nil {
		t.Fatalf("ListFindingsByRun() failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings after cascade delete, got %d", len(findings))
	}

	// Also verify the finding ID doesn't exist
	_ = findingID // Just to use the variable
}

// Helper functions - unique names to avoid redeclaration
var findingsTestCounter int

func createTestRunForFindings(t *testing.T, s *Store) int64 {
	t.Helper()
	ctx := context.Background()
	expID := createTestExperimentForFindings(t, s)
	scannerID := createTestScannerForFindings(t, s)
	projectID := createTestProjectForFindings(t, s)

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

func createTestExperimentForFindings(t *testing.T, s *Store) int64 {
	t.Helper()
	findingsTestCounter++
	ctx := context.Background()
	id, err := s.CreateExperiment(ctx, &Experiment{
		Name:       "test-experiment-findings-" + string(rune('a'+findingsTestCounter)),
		Iterations: 1,
	})
	if err != nil {
		t.Fatalf("CreateExperiment() failed: %v", err)
	}
	return id
}

func createTestScannerForFindings(t *testing.T, s *Store) int64 {
	t.Helper()
	findingsTestCounter++
	ctx := context.Background()
	id, err := s.CreateScanner(ctx, &Scanner{
		Name:        "test-scanner-findings-" + string(rune('a'+findingsTestCounter)),
		Version:     "1.0.0",
		DockerImage: "test-scanner:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}
	return id
}

func createTestProjectForFindings(t *testing.T, s *Store) int64 {
	t.Helper()
	findingsTestCounter++
	ctx := context.Background()
	id, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "test-project-findings-" + string(rune('a'+findingsTestCounter)),
		LocalPath: "/tmp/test",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}
	return id
}

func TestClearFindingMatchesForRun_DeletesDerivedNotPrimary(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()

	runID := createTestRunForFindings(t, s)
	findingID, _ := s.CreateFinding(ctx, &Finding{RunID: runID, FilePath: "a.go", StartLine: 10})
	projectID := createTestProjectForFindings(t, s)
	annID := createTestAnnotationForFindings(t, s, projectID)
	s.CreateFindingMatch(ctx, &FindingMatch{FindingID: findingID, AnnotationID: annID, MatchType: "exact"})

	// Precondition: match exists.
	before, _ := s.ListFindingMatchesByRun(ctx, runID)
	if len(before) != 1 {
		t.Fatalf("setup: want 1 match, got %d", len(before))
	}

	n, err := s.ClearFindingMatchesForRun(ctx, runID)
	if err != nil {
		t.Fatalf("ClearFindingMatchesForRun() failed: %v", err)
	}
	if n != 1 {
		t.Errorf("rows affected = %d, want 1", n)
	}

	// Match gone.
	after, _ := s.ListFindingMatchesByRun(ctx, runID)
	if len(after) != 0 {
		t.Errorf("want 0 matches after clear, got %d", len(after))
	}

	// Finding survives — this is the whole point. We're clearing
	// derived state, not primary data.
	findings, _ := s.ListFindingsByRun(ctx, runID)
	if len(findings) != 1 {
		t.Errorf("finding deleted — should only clear match rows. want 1 finding, got %d", len(findings))
	}
}

func TestClearFindingMatchesForRun_ScopedToOneRun(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()

	// Two runs, each with a match. Clear run A; run B's match survives.
	runA := createTestRunForFindings(t, s)
	runB := createTestRunForFindings(t, s)
	projectID := createTestProjectForFindings(t, s)
	annA := createTestAnnotationForFindings(t, s, projectID)
	annB := createTestAnnotationForFindings(t, s, projectID)

	fA, _ := s.CreateFinding(ctx, &Finding{RunID: runA, FilePath: "a.go", StartLine: 10})
	fB, _ := s.CreateFinding(ctx, &Finding{RunID: runB, FilePath: "b.go", StartLine: 20})
	s.CreateFindingMatch(ctx, &FindingMatch{FindingID: fA, AnnotationID: annA, MatchType: "exact"})
	s.CreateFindingMatch(ctx, &FindingMatch{FindingID: fB, AnnotationID: annB, MatchType: "exact"})

	s.ClearFindingMatchesForRun(ctx, runA)

	if got, _ := s.ListFindingMatchesByRun(ctx, runA); len(got) != 0 {
		t.Errorf("run A: want 0 matches after clear, got %d", len(got))
	}
	if got, _ := s.ListFindingMatchesByRun(ctx, runB); len(got) != 1 {
		t.Errorf("run B: matches leaked across runs — want 1, got %d", len(got))
	}
}

func createTestAnnotationForFindings(t *testing.T, s *Store, projectID int64) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := s.CreateAnnotation(ctx, &Annotation{
		ProjectID: projectID,
		FilePath:  "test.go",
		StartLine: 10,
		Category:  "sql-injection",
		Severity:  "high",
		Status:    "valid",
	})
	if err != nil {
		t.Fatalf("CreateAnnotation() failed: %v", err)
	}
	return id
}

func createTestAnnotationWithFileForFindings(t *testing.T, s *Store, projectID int64, filePath string) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := s.CreateAnnotation(ctx, &Annotation{
		ProjectID: projectID,
		FilePath:  filePath,
		StartLine: 10,
		Category:  "sql-injection",
		Severity:  "high",
		Status:    "valid",
	})
	if err != nil {
		t.Fatalf("CreateAnnotation() failed: %v", err)
	}
	return id
}
