package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/block/benchmrk/internal/store"
)

// resetRescoreFlags clears package-level flag state between test runs.
// Cobra keeps flag values across Execute() calls in the same process,
// so without this the second test sees the first test's --run value.
func resetRescoreFlags() {
	rescoreYes = false
	rescoreClearOnly = false
	rescoreRunID = 0
}

// rescoreFixture builds the minimum graph for a rescore happy path:
// a project with one annotation (so the empty-ground-truth guardrail
// passes), a completed run with one finding at the annotation's
// location (so MatchRun produces a match), and a manually-stamped
// stale annotation hash (so we can verify it gets re-stamped).
type rescoreFixture struct {
	projectName string
	runID       int64
	staleHash   string
}

func setupRescoreFixture(t *testing.T, tempDir string) rescoreFixture {
	t.Helper()
	ctx := context.Background()

	projectID, err := globalStore.CreateProject(ctx, &store.CorpusProject{
		Name:      "rescore-test-project",
		LocalPath: tempDir,
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	// One annotation at app.go:42. The finding below lands on the
	// same file+line so MatchRun produces an exact match.
	if _, err := globalStore.CreateAnnotation(ctx, &store.Annotation{
		ProjectID: projectID,
		FilePath:  "app.go",
		StartLine: 42,
		Category:  "sqli",
		Severity:  "high",
		Status:    "valid",
	}); err != nil {
		t.Fatalf("create annotation: %v", err)
	}

	scannerID, _ := globalStore.CreateScanner(ctx, &store.Scanner{
		Name: "rescore-test-scanner", Version: "1.0", DockerImage: "x:1",
	})
	expID, _ := globalStore.CreateExperiment(ctx, &store.Experiment{Name: "rescore-exp"})

	runID, err := globalStore.CreateRun(ctx, &store.Run{
		ExperimentID: expID,
		ScannerID:    scannerID,
		ProjectID:    projectID,
		Iteration:    1,
		Status:       store.RunStatusCompleted,
		StartedAt:    sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	if _, err := globalStore.CreateFinding(ctx, &store.Finding{
		RunID:     runID,
		FilePath:  "app.go",
		StartLine: 42,
	}); err != nil {
		t.Fatalf("create finding: %v", err)
	}

	// Stamp with a hash that can't be what AnnotationHash returns now.
	// After rescore, the run should carry the real hash.
	const stale = "deadbeefdeadbeef"
	if err := globalStore.StampRunScorer(ctx, runID, "3", stale); err != nil {
		t.Fatalf("stamp stale hash: %v", err)
	}

	return rescoreFixture{
		projectName: "rescore-test-project",
		runID:       runID,
		staleHash:   stale,
	}
}

func TestRescore_ClearsAndRestamps(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()

	fx := setupRescoreFixture(t, tempDir)
	ctx := context.Background()

	stdout, _, err := runCommand([]string{"rescore", fx.projectName, "--yes"})
	if err != nil {
		t.Fatalf("rescore failed: %v\n%s", err, stdout)
	}

	if !strings.Contains(stdout, "Cleared") {
		t.Errorf("expected 'Cleared' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, fmt.Sprintf("run %d", fx.runID)) {
		t.Errorf("expected progress line for run %d, got:\n%s", fx.runID, stdout)
	}

	// The run's annotation_hash should now be the project's CURRENT
	// hash, not the stale one we stamped. That's the whole purpose
	// of rescore — align every run to the same ground truth.
	run, _ := globalStore.GetRun(ctx, fx.runID)
	if run.AnnotationHash.String == fx.staleHash {
		t.Error("annotation_hash still stale after rescore — run was not re-stamped")
	}
	want, _ := globalStore.AnnotationHash(ctx, run.ProjectID)
	if run.AnnotationHash.String != want {
		t.Errorf("annotation_hash = %q, want current hash %q", run.AnnotationHash.String, want)
	}

	// MatchRun should have found the app.go:42 → app.go:42 match.
	matches, _ := globalStore.ListFindingMatchesByRun(ctx, fx.runID)
	if len(matches) != 1 {
		t.Errorf("want 1 match after rescore, got %d", len(matches))
	}
}

func TestRescore_ClearOnlySkipsRematch(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()

	fx := setupRescoreFixture(t, tempDir)

	_, _, err := runCommand([]string{"rescore", fx.projectName, "--yes", "--clear-only"})
	if err != nil {
		t.Fatalf("rescore --clear-only failed: %v", err)
	}

	// No matches — cleared but not rematched.
	matches, _ := globalStore.ListFindingMatchesByRun(context.Background(), fx.runID)
	if len(matches) != 0 {
		t.Errorf("--clear-only should not rematch; got %d matches", len(matches))
	}

	// Stamp NOT updated — StampRunScorer happens inside MatchRun,
	// which we skipped. The stale hash should survive.
	run, _ := globalStore.GetRun(context.Background(), fx.runID)
	if run.AnnotationHash.String != fx.staleHash {
		t.Error("--clear-only should not re-stamp; hash changed")
	}
}

func TestRescore_RefusesEmptyGroundTruth(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()
	ctx := context.Background()

	// Project with a completed run but NO annotations. Rescoring
	// against this would turn every former TP into an unmatched FP.
	projectID, _ := globalStore.CreateProject(ctx, &store.CorpusProject{
		Name: "empty-gt-project", LocalPath: tempDir,
	})
	scannerID, _ := globalStore.CreateScanner(ctx, &store.Scanner{
		Name: "empty-gt-scanner", Version: "1.0", DockerImage: "x:1",
	})
	expID, _ := globalStore.CreateExperiment(ctx, &store.Experiment{Name: "empty-gt-exp"})
	globalStore.CreateRun(ctx, &store.Run{
		ExperimentID: expID, ScannerID: scannerID, ProjectID: projectID,
		Iteration: 1, Status: store.RunStatusCompleted,
	})

	_, _, err := runCommand([]string{"rescore", "empty-gt-project", "--yes"})
	if err == nil {
		t.Fatal("expected error for empty ground truth, got nil")
	}
	if !strings.Contains(err.Error(), "no annotations") {
		t.Errorf("expected 'no annotations' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "annotate import") {
		t.Errorf("error should suggest the fix (annotate import), got: %v", err)
	}
}

func TestRescore_SingleRun(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()

	fx := setupRescoreFixture(t, tempDir)

	_, _, err := runCommand([]string{"rescore", "--run", fmt.Sprintf("%d", fx.runID), "--yes"})
	if err != nil {
		t.Fatalf("rescore --run failed: %v", err)
	}

	run, _ := globalStore.GetRun(context.Background(), fx.runID)
	if run.AnnotationHash.String == fx.staleHash {
		t.Error("--run <id> did not re-stamp the run")
	}
}

func TestRescore_RunNotCompleted(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()
	ctx := context.Background()

	projectID, _ := globalStore.CreateProject(ctx, &store.CorpusProject{
		Name: "pending-project", LocalPath: tempDir,
	})
	scannerID, _ := globalStore.CreateScanner(ctx, &store.Scanner{
		Name: "pending-scanner", Version: "1.0", DockerImage: "x:1",
	})
	expID, _ := globalStore.CreateExperiment(ctx, &store.Experiment{Name: "pending-exp"})
	runID, _ := globalStore.CreateRun(ctx, &store.Run{
		ExperimentID: expID, ScannerID: scannerID, ProjectID: projectID,
		Iteration: 1, Status: store.RunStatusPending,
	})

	_, _, err := runCommand([]string{"rescore", "--run", fmt.Sprintf("%d", runID), "--yes"})
	if err == nil {
		t.Fatal("expected error for pending run, got nil")
	}
	if !strings.Contains(err.Error(), "pending") || !strings.Contains(err.Error(), "completed") {
		t.Errorf("error should explain why (status) and what's required (completed), got: %v", err)
	}
}

func TestRescore_ProjectNotFound(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()

	_, _, err := runCommand([]string{"rescore", "no-such-project", "--yes"})
	if err == nil {
		t.Fatal("expected error for missing project, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestRescore_MutualExclusion(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()

	_, _, err := runCommand([]string{"rescore", "some-project", "--run", "5", "--yes"})
	if err == nil {
		t.Fatal("expected error when both project and --run given, got nil")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("expected 'not both' in error, got: %v", err)
	}
}

func TestRescore_NoScope(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetRescoreFlags()

	_, _, err := runCommand([]string{"rescore", "--yes"})
	if err == nil {
		t.Fatal("expected error when neither project nor --run given, got nil")
	}
}
