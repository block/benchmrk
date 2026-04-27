package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/block/benchmrk/internal/store"
)

// setupRunWithLog returns a run ID whose LogPath points at a temp file
// containing wantContent. The FK chain (project → scanner → experiment
// → run) is the minimum the schema requires.
func setupRunWithLog(t *testing.T, tempDir, wantContent string) int64 {
	t.Helper()
	ctx := context.Background()

	projectID, err := globalStore.CreateProject(ctx, &store.CorpusProject{
		Name:      "logs-test-project",
		LocalPath: tempDir,
	})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	scannerID, err := globalStore.CreateScanner(ctx, &store.Scanner{
		Name:        "logs-test-scanner",
		Version:     "1.0",
		DockerImage: "test:latest",
	})
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	expID, err := globalStore.CreateExperiment(ctx, &store.Experiment{Name: "logs-test-exp"})
	if err != nil {
		t.Fatalf("create experiment: %v", err)
	}

	var logPath sql.NullString
	if wantContent != "" {
		p := filepath.Join(tempDir, "scan.log")
		if err := os.WriteFile(p, []byte(wantContent), 0644); err != nil {
			t.Fatalf("write log file: %v", err)
		}
		logPath = sql.NullString{String: p, Valid: true}
	}

	runID, err := globalStore.CreateRun(ctx, &store.Run{
		ExperimentID: expID,
		ScannerID:    scannerID,
		ProjectID:    projectID,
		Iteration:    1,
		Status:       store.RunStatusCompleted,
		StartedAt:    sql.NullTime{Time: time.Now(), Valid: true},
		LogPath:      logPath,
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	return runID
}

func TestLogs_PrintsFileContents(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	want := "semgrep scanned 42 files\n[WARN] rule foo is deprecated\n"
	runID := setupRunWithLog(t, tempDir, want)

	stdout, _, err := runCommand([]string{"logs", fmt.Sprintf("%d", runID)})
	if err != nil {
		t.Fatalf("logs failed: %v", err)
	}
	if stdout != want {
		t.Errorf("output mismatch\nwant: %q\ngot:  %q", want, stdout)
	}
}

func TestLogs_NoLogsCaptured(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	runID := setupRunWithLog(t, tempDir, "") // empty → LogPath.Valid = false

	_, _, err := runCommand([]string{"logs", fmt.Sprintf("%d", runID)})
	if err == nil {
		t.Fatal("expected error for run with no logs, got nil")
	}
	if !strings.Contains(err.Error(), "no logs captured") {
		t.Errorf("expected 'no logs captured' in error, got: %v", err)
	}
}

func TestLogs_InvalidRunID(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"logs", "not-a-number"})
	if err == nil {
		t.Fatal("expected error for non-numeric run ID, got nil")
	}
	if !strings.Contains(err.Error(), "invalid run ID") {
		t.Errorf("expected 'invalid run ID' in error, got: %v", err)
	}
}

func TestImport_FileNotFound(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"import", "some-scanner", "some-project", "/nonexistent/results.sarif"})
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestReviewSarif_FileNotFound(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	// review sarif doesn't need a DB, but setupTestEnv resets flag state.
	_, _, err := runCommand([]string{"review", "sarif", "/nonexistent/out.sarif"})
	if err == nil {
		t.Fatal("expected error for missing SARIF file, got nil")
	}
}
