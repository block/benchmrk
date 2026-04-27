package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

func setupExperimentTestEnv(t *testing.T) func() {
	t.Helper()

	tempDir := t.TempDir()
	testDBPath := filepath.Join(tempDir, "test.db")

	s, err := store.New(testDBPath)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	oldStore := globalStore
	oldDBPath := dbPath
	globalStore = s
	dbPath = testDBPath

	return func() {
		globalStore = oldStore
		dbPath = oldDBPath
		s.Close()
	}
}

func createTestScannerAndProject(t *testing.T) (scannerID, projectID int64) {
	t.Helper()

	ctx := context.Background()

	sc := &store.Scanner{
		Name:        "test-scanner",
		Version:     "1.0",
		DockerImage: "test/scanner:1.0",
	}
	scannerID, err := globalStore.CreateScanner(ctx, sc)
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}

	tempDir := t.TempDir()
	projectPath := filepath.Join(tempDir, "test-project")
	if err := os.MkdirAll(projectPath, 0755); err != nil {
		t.Fatalf("create project dir: %v", err)
	}

	p := &store.CorpusProject{
		Name:      "test-project",
		LocalPath: projectPath,
	}
	projectID, err = globalStore.CreateProject(ctx, p)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	return scannerID, projectID
}

func resetExperimentFlags() {
	experimentCreateCmd.Flags().Set("description", "")
	experimentCreateCmd.Flags().Set("scanners", "")
	experimentCreateCmd.Flags().Set("projects", "")
	experimentCreateCmd.Flags().Set("iterations", "1")
	experimentRunCmd.Flags().Set("concurrency", "2")
	experimentResumeCmd.Flags().Set("concurrency", "2")
}

func runExperimentCommand(args []string) (string, string, error) {
	resetExperimentFlags()

	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	rootCmd.SetArgs(args)
	err := rootCmd.Execute()

	wOut.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutBuf.ReadFrom(rOut)
	stderrBuf.ReadFrom(rErr)

	return stdoutBuf.String(), stderrBuf.String(), err
}

func TestExperimentCreate_Success(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	scannerID, projectID := createTestScannerAndProject(t)

	stdout, _, err := runExperimentCommand([]string{
		"experiment", "create", "my-experiment",
		"--scanners", formatIDs(scannerID),
		"--projects", formatIDs(projectID),
		"--iterations", "3",
	})
	if err != nil {
		t.Fatalf("experiment create failed: %v", err)
	}

	if !strings.Contains(stdout, "Created experiment") {
		t.Errorf("expected 'Created experiment' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "my-experiment") {
		t.Errorf("expected 'my-experiment' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Iterations: 3") {
		t.Errorf("expected 'Iterations: 3' in output, got: %s", stdout)
	}
}

func TestExperimentCreate_ParsesCommaListCorrectly(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	ctx := context.Background()

	sc1 := &store.Scanner{Name: "scanner1", Version: "1.0", DockerImage: "s1:1.0"}
	id1, _ := globalStore.CreateScanner(ctx, sc1)
	sc2 := &store.Scanner{Name: "scanner2", Version: "1.0", DockerImage: "s2:1.0"}
	id2, _ := globalStore.CreateScanner(ctx, sc2)

	tempDir := t.TempDir()
	p1Path := filepath.Join(tempDir, "p1")
	p2Path := filepath.Join(tempDir, "p2")
	os.MkdirAll(p1Path, 0755)
	os.MkdirAll(p2Path, 0755)

	p1 := &store.CorpusProject{Name: "proj1", LocalPath: p1Path}
	pid1, _ := globalStore.CreateProject(ctx, p1)
	p2 := &store.CorpusProject{Name: "proj2", LocalPath: p2Path}
	pid2, _ := globalStore.CreateProject(ctx, p2)

	stdout, _, err := runExperimentCommand([]string{
		"experiment", "create", "multi-exp",
		"--scanners", formatIDs(id1, id2),
		"--projects", formatIDs(pid1, pid2),
		"--iterations", "2",
	})
	if err != nil {
		t.Fatalf("experiment create failed: %v", err)
	}

	if !strings.Contains(stdout, "Scanners: 2") {
		t.Errorf("expected 'Scanners: 2' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Projects: 2") {
		t.Errorf("expected 'Projects: 2' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Total runs: 8") {
		t.Errorf("expected 'Total runs: 8' (2×2×2) in output, got: %s", stdout)
	}
}

func TestExperimentCreate_ValidatesIterationsPositive(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	scannerID, projectID := createTestScannerAndProject(t)

	_, _, err := runExperimentCommand([]string{
		"experiment", "create", "bad-exp",
		"--scanners", formatIDs(scannerID),
		"--projects", formatIDs(projectID),
		"--iterations", "0",
	})
	if err == nil {
		t.Fatal("expected error for zero iterations, got nil")
	}
	if !strings.Contains(err.Error(), "positive") {
		t.Errorf("expected 'positive' in error, got: %v", err)
	}

	_, _, err = runExperimentCommand([]string{
		"experiment", "create", "bad-exp2",
		"--scanners", formatIDs(scannerID),
		"--projects", formatIDs(projectID),
		"--iterations", "-1",
	})
	if err == nil {
		t.Fatal("expected error for negative iterations, got nil")
	}
}

func TestExperimentList_ShowsAllExperiments(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	scannerID, projectID := createTestScannerAndProject(t)

	runExperimentCommand([]string{
		"experiment", "create", "exp-alpha",
		"--scanners", formatIDs(scannerID),
		"--projects", formatIDs(projectID),
	})
	runExperimentCommand([]string{
		"experiment", "create", "exp-beta",
		"--scanners", formatIDs(scannerID),
		"--projects", formatIDs(projectID),
	})

	stdout, _, err := runExperimentCommand([]string{"experiment", "list"})
	if err != nil {
		t.Fatalf("experiment list failed: %v", err)
	}

	if !strings.Contains(stdout, "exp-alpha") {
		t.Errorf("expected 'exp-alpha' in list, got: %s", stdout)
	}
	if !strings.Contains(stdout, "exp-beta") {
		t.Errorf("expected 'exp-beta' in list, got: %s", stdout)
	}
	if !strings.Contains(stdout, "ID") {
		t.Errorf("expected header 'ID' in list, got: %s", stdout)
	}
}

func TestExperimentList_NoExperiments(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	stdout, _, err := runExperimentCommand([]string{"experiment", "list"})
	if err != nil {
		t.Fatalf("experiment list failed: %v", err)
	}

	if !strings.Contains(stdout, "No experiments") {
		t.Errorf("expected 'No experiments' message, got: %s", stdout)
	}
}

func TestExperimentStatus_DisplaysCorrectRunCounts(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	scannerID, projectID := createTestScannerAndProject(t)

	runExperimentCommand([]string{
		"experiment", "create", "status-exp",
		"--scanners", formatIDs(scannerID),
		"--projects", formatIDs(projectID),
		"--iterations", "5",
	})

	stdout, _, err := runExperimentCommand([]string{"experiment", "status", "1"})
	if err != nil {
		t.Fatalf("experiment status failed: %v", err)
	}

	if !strings.Contains(stdout, "status-exp") {
		t.Errorf("expected 'status-exp' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Total runs: 5") {
		t.Errorf("expected 'Total runs: 5' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Pending:") {
		t.Errorf("expected 'Pending:' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Completed:") {
		t.Errorf("expected 'Completed:' in output, got: %s", stdout)
	}
}

func TestExperimentResults_DisplaysMetricsMatrix(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	ctx := context.Background()

	sc1 := &store.Scanner{Name: "semgrep", Version: "1.0", DockerImage: "s:1"}
	sid1, _ := globalStore.CreateScanner(ctx, sc1)
	sc2 := &store.Scanner{Name: "codeql", Version: "2.0", DockerImage: "c:2"}
	sid2, _ := globalStore.CreateScanner(ctx, sc2)

	tempDir := t.TempDir()
	p1Path := filepath.Join(tempDir, "webapp")
	os.MkdirAll(p1Path, 0755)
	p1 := &store.CorpusProject{Name: "webapp", LocalPath: p1Path}
	pid1, _ := globalStore.CreateProject(ctx, p1)

	runExperimentCommand([]string{
		"experiment", "create", "results-exp",
		"--scanners", formatIDs(sid1, sid2),
		"--projects", formatIDs(pid1),
	})

	stdout, _, err := runExperimentCommand([]string{"experiment", "results", "1"})
	if err != nil {
		t.Fatalf("experiment results failed: %v", err)
	}

	if !strings.Contains(stdout, "results-exp") {
		t.Errorf("expected 'results-exp' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "SCANNER") {
		t.Errorf("expected header 'SCANNER' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "webapp") {
		t.Errorf("expected 'webapp' column in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "semgrep") {
		t.Errorf("expected 'semgrep' row in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "codeql") {
		t.Errorf("expected 'codeql' row in output, got: %s", stdout)
	}
}

func TestExperimentShow_NotFound(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	_, _, err := runExperimentCommand([]string{"experiment", "show", "9999"})
	if err == nil {
		t.Fatal("expected error for non-existent experiment, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestExperimentStatus_InvalidID(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	_, _, err := runExperimentCommand([]string{"experiment", "status", "9999"})
	if err == nil {
		t.Fatal("expected error for non-existent experiment, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestExperimentDelete_Success(t *testing.T) {
	cleanup := setupExperimentTestEnv(t)
	defer cleanup()

	scannerID, projectID := createTestScannerAndProject(t)

	runExperimentCommand([]string{
		"experiment", "create", "to-delete",
		"--scanners", formatIDs(scannerID),
		"--projects", formatIDs(projectID),
	})

	stdout, _, err := runExperimentCommand([]string{"experiment", "delete", "1"})
	if err != nil {
		t.Fatalf("experiment delete failed: %v", err)
	}

	if !strings.Contains(stdout, "Deleted") {
		t.Errorf("expected 'Deleted' in output, got: %s", stdout)
	}

	_, _, err = runExperimentCommand([]string{"experiment", "show", "1"})
	if err == nil {
		t.Error("expected error after deletion, but experiment still exists")
	}
}

func TestExperimentHelp_ShowsUsage(t *testing.T) {
	oldStore := globalStore
	globalStore = nil
	defer func() { globalStore = oldStore }()

	stdout, _, _ := runExperimentCommand([]string{"experiment", "--help"})

	expectedElements := []string{
		"experiment",
		"create",
		"list",
		"run",
		"resume",
		"status",
		"results",
		"delete",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in help output, got: %s", elem, stdout)
		}
	}
}

func formatIDs(ids ...int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return strings.Join(parts, ",")
}
