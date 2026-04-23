package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/block/benchmrk/internal/store"
)

func resetAnalyzeFlags() {
	compareCmd.Flags().Set("project", "")
}

// setupAnalysisTestEnv creates a test environment with scanners, projects, runs, and findings
func setupAnalysisTestEnv(t *testing.T) (scannerA, scannerB *store.Scanner, project *store.CorpusProject, runA, runB *store.Run, cleanup func()) {
	t.Helper()

	tempDir, baseCleanup := setupTestEnv(t)

	ctx := context.Background()

	// Create a project
	projectID, err := globalStore.CreateProject(ctx, &store.CorpusProject{
		Name:      "test-project",
		LocalPath: tempDir,
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	project, err = globalStore.GetProject(ctx, projectID)
	if err != nil {
		t.Fatalf("get project: %v", err)
	}

	// Create scanners
	scannerAID, err := globalStore.CreateScanner(ctx, &store.Scanner{
		Name:        "scanner-a",
		Version:     "1.0",
		DockerImage: "scanner-a:latest",
	})
	if err != nil {
		t.Fatalf("create scanner A: %v", err)
	}
	scannerA, err = globalStore.GetScanner(ctx, scannerAID)
	if err != nil {
		t.Fatalf("get scanner A: %v", err)
	}

	scannerBID, err := globalStore.CreateScanner(ctx, &store.Scanner{
		Name:        "scanner-b",
		Version:     "1.0",
		DockerImage: "scanner-b:latest",
	})
	if err != nil {
		t.Fatalf("create scanner B: %v", err)
	}
	scannerB, err = globalStore.GetScanner(ctx, scannerBID)
	if err != nil {
		t.Fatalf("get scanner B: %v", err)
	}

	// Create an experiment
	experimentID, err := globalStore.CreateExperiment(ctx, &store.Experiment{
		Name:        "test-experiment",
		Description: sql.NullString{String: "Test experiment", Valid: true},
	})
	if err != nil {
		t.Fatalf("create experiment: %v", err)
	}

	// Link scanners and projects to experiment
	if err := globalStore.AddScannerToExperiment(ctx, experimentID, scannerAID); err != nil {
		t.Fatalf("add scanner A to experiment: %v", err)
	}
	if err := globalStore.AddScannerToExperiment(ctx, experimentID, scannerBID); err != nil {
		t.Fatalf("add scanner B to experiment: %v", err)
	}
	if err := globalStore.AddProjectToExperiment(ctx, experimentID, projectID); err != nil {
		t.Fatalf("add project to experiment: %v", err)
	}

	// Create runs
	runAID, err := globalStore.CreateRun(ctx, &store.Run{
		ExperimentID: experimentID,
		ScannerID:    scannerAID,
		ProjectID:    projectID,
		Iteration:    1,
		Status:       store.RunStatusCompleted,
		StartedAt:    sql.NullTime{Time: time.Now(), Valid: true},
		CompletedAt:  sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		t.Fatalf("create run A: %v", err)
	}
	runA, err = globalStore.GetRun(ctx, runAID)
	if err != nil {
		t.Fatalf("get run A: %v", err)
	}

	runBID, err := globalStore.CreateRun(ctx, &store.Run{
		ExperimentID: experimentID,
		ScannerID:    scannerBID,
		ProjectID:    projectID,
		Iteration:    1,
		Status:       store.RunStatusCompleted,
		StartedAt:    sql.NullTime{Time: time.Now(), Valid: true},
		CompletedAt:  sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		t.Fatalf("create run B: %v", err)
	}
	runB, err = globalStore.GetRun(ctx, runBID)
	if err != nil {
		t.Fatalf("get run B: %v", err)
	}

	// Create annotations (ground truth)
	annotationID, err := globalStore.CreateAnnotation(ctx, &store.Annotation{
		ProjectID: projectID,
		FilePath:  "src/main.go",
		StartLine: 10,
		Status:    "valid",
		Category:  "sql-injection",
		Severity:  "high",
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	})
	if err != nil {
		t.Fatalf("create annotation: %v", err)
	}

	// Create findings for run A - 1 TP, 1 FP
	findingA1ID, err := globalStore.CreateFinding(ctx, &store.Finding{
		RunID:     runAID,
		RuleID:    sql.NullString{String: "sql-injection-rule", Valid: true},
		FilePath:  "src/main.go",
		StartLine: 10,
		Severity:  sql.NullString{String: "high", Valid: true},
		Message:   sql.NullString{String: "SQL injection found", Valid: true},
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	})
	if err != nil {
		t.Fatalf("create finding A1: %v", err)
	}

	// Match finding A1 with annotation
	if _, err := globalStore.CreateFindingMatch(ctx, &store.FindingMatch{
		FindingID:    findingA1ID,
		AnnotationID: annotationID,
		MatchType:    "exact",
		Confidence:   sql.NullFloat64{Float64: 1.0, Valid: true},
	}); err != nil {
		t.Fatalf("create finding match: %v", err)
	}

	// Create an unmatched finding (FP)
	if _, err := globalStore.CreateFinding(ctx, &store.Finding{
		RunID:     runAID,
		RuleID:    sql.NullString{String: "false-positive-rule", Valid: true},
		FilePath:  "src/other.go",
		StartLine: 50,
		Severity:  sql.NullString{String: "low", Valid: true},
		Message:   sql.NullString{String: "False positive", Valid: true},
	}); err != nil {
		t.Fatalf("create finding A2: %v", err)
	}

	// Create findings for run B - 1 TP only (better precision)
	findingB1ID, err := globalStore.CreateFinding(ctx, &store.Finding{
		RunID:     runBID,
		RuleID:    sql.NullString{String: "sql-injection-rule", Valid: true},
		FilePath:  "src/main.go",
		StartLine: 10,
		Severity:  sql.NullString{String: "high", Valid: true},
		Message:   sql.NullString{String: "SQL injection detected", Valid: true},
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	})
	if err != nil {
		t.Fatalf("create finding B1: %v", err)
	}

	// Match finding B1 with annotation
	if _, err := globalStore.CreateFindingMatch(ctx, &store.FindingMatch{
		FindingID:    findingB1ID,
		AnnotationID: annotationID,
		MatchType:    "exact",
		Confidence:   sql.NullFloat64{Float64: 1.0, Valid: true},
	}); err != nil {
		t.Fatalf("create finding match B1: %v", err)
	}

	cleanup = func() {
		resetAnalyzeFlags()
		baseCleanup()
	}

	return scannerA, scannerB, project, runA, runB, cleanup
}

func TestAnalyzeRun_DisplaysMetrics(t *testing.T) {
	_, _, _, runA, _, cleanup := setupAnalysisTestEnv(t)
	defer cleanup()

	stdout, _, err := runCommand([]string{"analyze", "1"})
	if err != nil {
		t.Fatalf("analyze run failed: %v", err)
	}

	// Verify metrics are displayed
	expectedElements := []string{
		"METRIC",
		"VALUE",
		"True Positives",
		"False Positives",
		"False Negatives",
		"Precision",
		"Recall",
		"F1",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in output, got: %s", elem, stdout)
		}
	}

	// Run A has 1 TP, 1 FP, 0 FN
	if !strings.Contains(stdout, "1") {
		t.Errorf("expected TP count in output, got: %s", stdout)
	}

	// Suppress unused variable warning
	_ = runA
}

func TestAnalyzeExperiment_DisplaysAggregatedMetrics(t *testing.T) {
	_, _, _, _, _, cleanup := setupAnalysisTestEnv(t)
	defer cleanup()

	stdout, _, err := runCommand([]string{"analyze", "experiment", "1"})
	if err != nil {
		t.Fatalf("analyze experiment failed: %v", err)
	}

	// Verify matrix output
	expectedElements := []string{
		"SCANNER",
		"scanner-a",
		"scanner-b",
		"test-project",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in output, got: %s", elem, stdout)
		}
	}
}

func TestCompare_ShowsSideBySideMetrics(t *testing.T) {
	_, _, _, _, _, cleanup := setupAnalysisTestEnv(t)
	defer cleanup()

	stdout, _, err := runCommand([]string{"compare", "scanner-a", "scanner-b", "--project", "test-project"})
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}

	// Verify comparison output
	expectedElements := []string{
		"Comparing",
		"scanner-a",
		"scanner-b",
		"test-project",
		"METRIC",
		"BEST",
		"TP",
		"FP",
		"Precision",
		"Recall",
		"F1",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in output, got: %s", elem, stdout)
		}
	}
}

func TestAnalyze_InvalidRunID(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"analyze", "999"})
	if err == nil {
		t.Fatal("expected error for invalid run ID, got nil")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "not found") && !strings.Contains(errStr, "analyze run") {
		t.Errorf("expected error about not found or analyze run, got: %v", err)
	}
}

func TestCompare_NonExistentScanner(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"compare", "nonexistent-scanner", "other-scanner", "--project", "test-project"})
	if err == nil {
		t.Fatal("expected error for non-existent scanner, got nil")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "not found") && !strings.Contains(errStr, "scanner") {
		t.Errorf("expected error about scanner not found, got: %v", err)
	}
}

func TestCompare_MissingProjectFlag(t *testing.T) {
	// Use a valid store to avoid PersistentPreRunE errors
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetAnalyzeFlags()

	// Ensure project flag is empty
	resetAnalyzeFlags()

	// Create scanners first to get past scanner lookup
	ctx := context.Background()
	_, err := globalStore.CreateScanner(ctx, &store.Scanner{
		Name:        "scanner-a",
		Version:     "1.0",
		DockerImage: "scanner-a:latest",
	})
	if err != nil {
		t.Fatalf("create scanner-a: %v", err)
	}
	_, err = globalStore.CreateScanner(ctx, &store.Scanner{
		Name:        "scanner-b",
		Version:     "1.0",
		DockerImage: "scanner-b:latest",
	})
	if err != nil {
		t.Fatalf("create scanner-b: %v", err)
	}

	// Now test without --project flag - reset again just before call
	resetAnalyzeFlags()
	_, _, err = runCommand([]string{"compare", "scanner-a", "scanner-b"})
	if err == nil {
		t.Fatal("expected error for missing --project flag, got nil")
	}

	if !strings.Contains(err.Error(), "--project") && !strings.Contains(err.Error(), "required") {
		t.Errorf("expected error about --project flag, got: %v", err)
	}
}

func TestAnalyzeHelp_ShowsUsage(t *testing.T) {
	oldStore := globalStore
	globalStore = nil
	defer func() { globalStore = oldStore }()

	stdout, _, _ := runCommand([]string{"analyze", "--help"})

	expectedElements := []string{
		"analyze",
		"run-id",
		"experiment",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in help output, got: %s", elem, stdout)
		}
	}
}

func TestCompareHelp_ShowsUsage(t *testing.T) {
	oldStore := globalStore
	globalStore = nil
	defer func() { globalStore = oldStore }()

	stdout, _, _ := runCommand([]string{"compare", "--help"})

	expectedElements := []string{
		"compare",
		"scanner-a",
		"scanner-b",
		"--project",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in help output, got: %s", elem, stdout)
		}
	}
}
