package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootCommand_DBFlag(t *testing.T) {
	// Reset state
	globalStore = nil
	defer func() { globalStore = nil }()

	tempDir := t.TempDir()
	testDB := filepath.Join(tempDir, "test.db")

	// Set dbPath directly (simulating flag parsing)
	oldDBPath := dbPath
	dbPath = testDB
	defer func() { dbPath = oldDBPath }()

	// Execute migrate command to trigger pre-run
	oldArgs := os.Args
	os.Args = []string{"benchmrk", "migrate", "--db", testDB}
	defer func() { os.Args = oldArgs }()

	// Create a new command for testing to avoid state pollution
	rootCmd.SetArgs([]string{"migrate", "--db", testDB})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify database was created at the expected path
	if _, err := os.Stat(testDB); os.IsNotExist(err) {
		t.Errorf("expected database file at %s, but it doesn't exist", testDB)
	}
}

func TestRootCommand_VerboseFlag(t *testing.T) {
	// Reset state
	globalStore = nil
	defer func() { globalStore = nil }()

	tempDir := t.TempDir()
	testDB := filepath.Join(tempDir, "verbose-test.db")

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() {
		os.Stderr = oldStderr
	}()

	// Execute with verbose flag
	rootCmd.SetArgs([]string{"--verbose", "--db", testDB, "migrate"})
	err := rootCmd.Execute()

	// Close writer and restore stderr before reading
	w.Close()
	os.Stderr = oldStderr

	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Read captured output
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify verbose output was printed
	if !strings.Contains(output, "Using database:") {
		t.Errorf("expected verbose output to contain 'Using database:', got: %s", output)
	}
}

func TestMigrateCommand_RunsMigrations(t *testing.T) {
	// Reset state
	globalStore = nil
	defer func() { globalStore = nil }()

	tempDir := t.TempDir()
	testDB := filepath.Join(tempDir, "migrate-test.db")

	// Execute migrate command
	rootCmd.SetArgs([]string{"--db", testDB, "migrate"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("migrate command failed: %v", err)
	}

	// Verify database was created
	if _, err := os.Stat(testDB); os.IsNotExist(err) {
		t.Errorf("expected database file at %s", testDB)
	}

	// Run migrate again to verify idempotency
	globalStore = nil
	rootCmd.SetArgs([]string{"--db", testDB, "migrate"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("second migrate command failed (not idempotent): %v", err)
	}
}

func TestRootCommand_HelpOutput(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rootCmd.SetArgs([]string{"--help"})
	_ = rootCmd.Execute() // Help returns nil error

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Verify expected elements in help output
	expectedElements := []string{
		"benchmrk",
		"static analysis scanners",
		"--db",
		"--verbose",
		"migrate",
		"--help",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(output, elem) {
			t.Errorf("expected help output to contain %q, got: %s", elem, output)
		}
	}
}

func TestRootCommand_CustomDBPath(t *testing.T) {
	// Reset state
	globalStore = nil
	defer func() { globalStore = nil }()

	tempDir := t.TempDir()
	customPath := filepath.Join(tempDir, "custom", "path", "test.db")

	// Execute migrate with custom path
	rootCmd.SetArgs([]string{"--db", customPath, "migrate"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}

	// Verify database was created at custom path
	if _, err := os.Stat(customPath); os.IsNotExist(err) {
		t.Errorf("expected database file at custom path %s", customPath)
	}
}
