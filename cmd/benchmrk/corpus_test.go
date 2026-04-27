package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

func setupTestEnv(t *testing.T) (string, func()) {
	t.Helper()

	tempDir := t.TempDir()
	testDBPath := filepath.Join(tempDir, "test.db")

	// Initialize store
	s, err := store.New(testDBPath)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Set global store and dbPath so PersistentPreRunE uses our migrated store
	oldStore := globalStore
	oldDBPath := dbPath
	globalStore = s
	dbPath = testDBPath

	cleanup := func() {
		globalStore = oldStore
		dbPath = oldDBPath
		s.Close()
	}

	return tempDir, cleanup
}

func runCommand(args []string) (string, string, error) {
	// Reset flags to defaults before running - Cobra keeps flag state between runs
	corpusAddCmd.Flags().Set("source", "")
	corpusAddCmd.Flags().Set("language", "")
	corpusAddCmd.Flags().Set("commit", "")

	// Capture stdout
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	// Capture stderr
	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	rootCmd.SetArgs(args)
	err := rootCmd.Execute()

	// Restore and read outputs
	wOut.Close()
	wErr.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutBuf.ReadFrom(rOut)
	stderrBuf.ReadFrom(rErr)

	return stdoutBuf.String(), stderrBuf.String(), err
}

func TestCorpusAdd_Success(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Create a test directory with some files
	testProject := filepath.Join(tempDir, "test-project")
	if err := os.MkdirAll(testProject, 0755); err != nil {
		t.Fatalf("create test project dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(testProject, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	stdout, _, err := runCommand([]string{"corpus", "add", "myproject", "--source", testProject})
	if err != nil {
		t.Fatalf("corpus add failed: %v", err)
	}

	if !strings.Contains(stdout, "Added project") {
		t.Errorf("expected 'Added project' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "myproject") {
		t.Errorf("expected 'myproject' in output, got: %s", stdout)
	}
}

func TestCorpusAdd_WithLanguage(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	testProject := filepath.Join(tempDir, "python-project")
	if err := os.MkdirAll(testProject, 0755); err != nil {
		t.Fatalf("create test project dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(testProject, "app.py"), []byte("print('hi')"), 0644); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	stdout, _, err := runCommand([]string{"corpus", "add", "pyproj", "--source", testProject, "--language", "python"})
	if err != nil {
		t.Fatalf("corpus add failed: %v", err)
	}

	if !strings.Contains(stdout, "python") {
		t.Errorf("expected 'python' in output, got: %s", stdout)
	}
}

func TestCorpusAdd_NonExistentPath(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"corpus", "add", "badproject", "--source", "/nonexistent/path/xyz"})
	if err == nil {
		t.Fatal("expected error for non-existent path, got nil")
	}

	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' in error, got: %v", err)
	}
}

func TestCorpusAdd_MissingSource(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"corpus", "add", "noproject"})
	if err == nil {
		t.Fatal("expected error for missing --source, got nil")
	}

	if !strings.Contains(err.Error(), "--source") && !strings.Contains(err.Error(), "required") {
		t.Errorf("expected error about --source or required, got: %v", err)
	}
}

func TestCorpusAdd_DuplicateName(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	testProject := filepath.Join(tempDir, "dup-project")
	if err := os.MkdirAll(testProject, 0755); err != nil {
		t.Fatalf("create test project dir: %v", err)
	}

	// Add first project
	_, _, err := runCommand([]string{"corpus", "add", "dupname", "--source", testProject})
	if err != nil {
		t.Fatalf("first add failed: %v", err)
	}

	// Try to add second project with same name
	_, _, err = runCommand([]string{"corpus", "add", "dupname", "--source", testProject})
	if err == nil {
		t.Fatal("expected error for duplicate name, got nil")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

func TestCorpusList_ShowsProjects(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	// Add two projects
	proj1 := filepath.Join(tempDir, "proj1")
	proj2 := filepath.Join(tempDir, "proj2")
	os.MkdirAll(proj1, 0755)
	os.MkdirAll(proj2, 0755)

	runCommand([]string{"corpus", "add", "alpha", "--source", proj1, "--language", "go"})
	runCommand([]string{"corpus", "add", "beta", "--source", proj2, "--language", "python"})

	stdout, _, err := runCommand([]string{"corpus", "list"})
	if err != nil {
		t.Fatalf("corpus list failed: %v", err)
	}

	if !strings.Contains(stdout, "alpha") {
		t.Errorf("expected 'alpha' in list, got: %s", stdout)
	}
	if !strings.Contains(stdout, "beta") {
		t.Errorf("expected 'beta' in list, got: %s", stdout)
	}
	if !strings.Contains(stdout, "NAME") {
		t.Errorf("expected header 'NAME' in list, got: %s", stdout)
	}
}

func TestCorpusList_NoProjects(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	stdout, _, err := runCommand([]string{"corpus", "list"})
	if err != nil {
		t.Fatalf("corpus list failed: %v", err)
	}

	if !strings.Contains(stdout, "No projects") {
		t.Errorf("expected 'No projects' message, got: %s", stdout)
	}
}

func TestCorpusShow_DisplaysDetails(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	testProject := filepath.Join(tempDir, "show-project")
	os.MkdirAll(testProject, 0755)

	runCommand([]string{"corpus", "add", "showme", "--source", testProject, "--language", "rust", "--commit", "abc123def"})

	stdout, _, err := runCommand([]string{"corpus", "show", "showme"})
	if err != nil {
		t.Fatalf("corpus show failed: %v", err)
	}

	expectedFields := []string{
		"Name:",
		"showme",
		"Path:",
		"Language:",
		"rust",
		"Commit:",
		"abc123def",
	}

	for _, field := range expectedFields {
		if !strings.Contains(stdout, field) {
			t.Errorf("expected %q in show output, got: %s", field, stdout)
		}
	}
}

func TestCorpusShow_NotFound(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"corpus", "show", "nonexistent"})
	if err == nil {
		t.Fatal("expected error for non-existent project, got nil")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestCorpusRemove_DeletesProject(t *testing.T) {
	tempDir, cleanup := setupTestEnv(t)
	defer cleanup()

	testProject := filepath.Join(tempDir, "to-remove")
	os.MkdirAll(testProject, 0755)

	runCommand([]string{"corpus", "add", "removeme", "--source", testProject})

	stdout, _, err := runCommand([]string{"corpus", "remove", "removeme"})
	if err != nil {
		t.Fatalf("corpus remove failed: %v", err)
	}

	if !strings.Contains(stdout, "Removed") {
		t.Errorf("expected 'Removed' in output, got: %s", stdout)
	}

	// Verify it's gone
	_, _, err = runCommand([]string{"corpus", "show", "removeme"})
	if err == nil {
		t.Error("expected error after removal, but project still exists")
	}
}

func TestCorpusRemove_NotFound(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"corpus", "remove", "nonexistent"})
	if err == nil {
		t.Fatal("expected error for non-existent project, got nil")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestCorpusHelp_ShowsUsage(t *testing.T) {
	// Reset global store to nil to skip initialization
	oldStore := globalStore
	globalStore = nil
	defer func() { globalStore = oldStore }()

	stdout, _, _ := runCommand([]string{"corpus", "--help"})

	expectedElements := []string{
		"corpus",
		"add",
		"list",
		"show",
		"remove",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in help output, got: %s", elem, stdout)
		}
	}
}
