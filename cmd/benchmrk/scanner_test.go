package main

import (
	"context"
	"strings"
	"testing"
)

func resetScannerFlags() {
	scannerRegisterCmd.Flags().Set("version", "")
	scannerRegisterCmd.Flags().Set("image", "")
	scannerRegisterCmd.Flags().Set("config", "")
	scannerRegisterCmd.Flags().Set("output-format", "")
}

func TestScannerRegister_Success(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	stdout, _, err := runCommand([]string{
		"scanner", "register", "semgrep",
		"--version", "1.0.0",
		"--image", "returntocorp/semgrep:latest",
	})
	if err != nil {
		t.Fatalf("scanner register failed: %v", err)
	}

	if !strings.Contains(stdout, "Registered scanner") {
		t.Errorf("expected 'Registered scanner' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "semgrep") {
		t.Errorf("expected 'semgrep' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "1.0.0") {
		t.Errorf("expected '1.0.0' in output, got: %s", stdout)
	}
}

func TestScannerRegister_WithConfig(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	configJSON := `{"rules":["p/default"]}`
	stdout, _, err := runCommand([]string{
		"scanner", "register", "codeql",
		"--version", "2.0.0",
		"--image", "github/codeql-action:latest",
		"--config", configJSON,
	})
	if err != nil {
		t.Fatalf("scanner register failed: %v", err)
	}

	if !strings.Contains(stdout, "Config:") {
		t.Errorf("expected 'Config:' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "rules") {
		t.Errorf("expected config JSON in output, got: %s", stdout)
	}
}

func TestScannerRegister_MissingVersion(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	_, _, err := runCommand([]string{
		"scanner", "register", "test-scanner",
		"--image", "test/image:latest",
	})
	if err == nil {
		t.Fatal("expected error for missing --version, got nil")
	}

	if !strings.Contains(err.Error(), "--version") {
		t.Errorf("expected error about --version, got: %v", err)
	}
}

func TestScannerRegister_MissingImage(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	_, _, err := runCommand([]string{
		"scanner", "register", "test-scanner",
		"--version", "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for missing --image, got nil")
	}

	if !strings.Contains(err.Error(), "--image") {
		t.Errorf("expected error about --image, got: %v", err)
	}
}

func TestScannerRegister_Duplicate(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	// Register first scanner
	_, _, err := runCommand([]string{
		"scanner", "register", "dup-scanner",
		"--version", "1.0.0",
		"--image", "test/image:v1",
	})
	if err != nil {
		t.Fatalf("first register failed: %v", err)
	}

	resetScannerFlags()

	// Try to register duplicate
	_, _, err = runCommand([]string{
		"scanner", "register", "dup-scanner",
		"--version", "1.0.0",
		"--image", "test/image:v2",
	})
	if err == nil {
		t.Fatal("expected error for duplicate scanner, got nil")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

func TestScannerList_ShowsScanners(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	// Register two scanners
	_, _, err := runCommand([]string{
		"scanner", "register", "alpha",
		"--version", "1.0.0",
		"--image", "alpha/scanner:latest",
	})
	if err != nil {
		t.Fatalf("register alpha failed: %v", err)
	}

	resetScannerFlags()

	_, _, err = runCommand([]string{
		"scanner", "register", "beta",
		"--version", "2.0.0",
		"--image", "beta/scanner:latest",
	})
	if err != nil {
		t.Fatalf("register beta failed: %v", err)
	}

	stdout, _, err := runCommand([]string{"scanner", "list"})
	if err != nil {
		t.Fatalf("scanner list failed: %v", err)
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
	if !strings.Contains(stdout, "VERSION") {
		t.Errorf("expected header 'VERSION' in list, got: %s", stdout)
	}
	if !strings.Contains(stdout, "IMAGE") {
		t.Errorf("expected header 'IMAGE' in list, got: %s", stdout)
	}
}

func TestScannerList_NoScanners(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	stdout, _, err := runCommand([]string{"scanner", "list"})
	if err != nil {
		t.Fatalf("scanner list failed: %v", err)
	}

	if !strings.Contains(stdout, "No scanners") {
		t.Errorf("expected 'No scanners' message, got: %s", stdout)
	}
}

func TestScan_NonExistentScanner(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	// Note: We can't actually run the scan command without Docker,
	// but we can test that it fails with a clear error for non-existent scanner.
	// Since scan requires Docker, we test the error case where Docker isn't available
	// or scanner doesn't exist.

	// First, let's at least verify the command parsing works
	_, _, err := runCommand([]string{"scan", "nonexistent", "project"})

	// The error could be either "docker not found" or "scanner not found" depending on env
	if err == nil {
		t.Fatal("expected error for non-existent scanner or docker, got nil")
	}

	// We accept either docker error or scanner error as valid
	errStr := err.Error()
	hasValidError := strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "docker") ||
		strings.Contains(errStr, "scanner")
	if !hasValidError {
		t.Errorf("expected meaningful error message, got: %v", err)
	}
}

func TestScan_NonExistentProject(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	// This test is similar to the above - we can't run without Docker
	// but we verify error handling
	_, _, err := runCommand([]string{"scan", "scanner", "nonexistent-project"})

	if err == nil {
		t.Fatal("expected error for non-existent project or docker, got nil")
	}

	// We accept either docker error or project error as valid
	errStr := err.Error()
	hasValidError := strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "docker") ||
		strings.Contains(errStr, "project")
	if !hasValidError {
		t.Errorf("expected meaningful error message, got: %v", err)
	}
}

func TestScannerHelp_ShowsUsage(t *testing.T) {
	// Reset global store to nil to skip initialization
	oldStore := globalStore
	globalStore = nil
	defer func() { globalStore = oldStore }()

	stdout, _, _ := runCommand([]string{"scanner", "--help"})

	expectedElements := []string{
		"scanner",
		"register",
		"list",
		"remove",
		"build",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in help output, got: %s", elem, stdout)
		}
	}
}

func TestScannerRegister_WithOutputFormat(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	stdout, _, err := runCommand([]string{
		"scanner", "register", "semgrep-native",
		"--version", "1.50.0",
		"--image", "returntocorp/semgrep:latest",
		"--output-format", "semgrep-json",
	})
	if err != nil {
		t.Fatalf("scanner register failed: %v", err)
	}

	if !strings.Contains(stdout, "Registered scanner") {
		t.Errorf("expected 'Registered scanner' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "Config:") {
		t.Errorf("expected 'Config:' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "semgrep-json") {
		t.Errorf("expected 'semgrep-json' in config output, got: %s", stdout)
	}

	// Verify stored config via store
	ctx := context.Background()
	sc, err := globalStore.GetScannerByNameVersion(ctx, "semgrep-native", "1.50.0")
	if err != nil {
		t.Fatalf("get scanner: %v", err)
	}
	if !sc.ConfigJSON.Valid || !strings.Contains(sc.ConfigJSON.String, "semgrep-json") {
		t.Errorf("expected config_json to contain 'semgrep-json', got: %v", sc.ConfigJSON)
	}
}

func TestScannerRegister_InvalidConfig(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	_, _, err := runCommand([]string{
		"scanner", "register", "bad-scanner",
		"--version", "1.0.0",
		"--image", "test:latest",
		"--config", `{invalid json`,
	})
	if err == nil {
		t.Fatal("expected error for invalid config JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid config") {
		t.Errorf("expected 'invalid config' error, got: %v", err)
	}
}

func TestScannerRegister_OutputFormatIgnoredWhenConfigProvided(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	// When both --config and --output-format are provided, --config takes precedence
	stdout, _, err := runCommand([]string{
		"scanner", "register", "custom-scanner",
		"--version", "1.0.0",
		"--image", "test:latest",
		"--config", `{"output_format":"sarif","env":{"RULES":"custom"}}`,
		"--output-format", "semgrep-json",
	})
	if err != nil {
		t.Fatalf("scanner register failed: %v", err)
	}

	// Config flag should be used as-is
	if !strings.Contains(stdout, "sarif") {
		t.Errorf("expected config with 'sarif' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "RULES") {
		t.Errorf("expected config with 'RULES' in output, got: %s", stdout)
	}
}

func TestScannerRemove_Success(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetScannerFlags()

	// Register a scanner first
	_, _, err := runCommand([]string{
		"scanner", "register", "removable",
		"--version", "1.0.0",
		"--image", "test/removable:latest",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	resetScannerFlags()

	// Remove it
	stdout, _, err := runCommand([]string{"scanner", "remove", "removable"})
	if err != nil {
		t.Fatalf("scanner remove failed: %v", err)
	}

	if !strings.Contains(stdout, "Removed scanner") {
		t.Errorf("expected 'Removed scanner' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "removable") {
		t.Errorf("expected 'removable' in output, got: %s", stdout)
	}

	// Verify it's gone
	listOut, _, err := runCommand([]string{"scanner", "list"})
	if err != nil {
		t.Fatalf("scanner list failed: %v", err)
	}
	if strings.Contains(listOut, "removable") {
		t.Errorf("scanner should be removed, but still in list: %s", listOut)
	}
}

func TestScannerRemove_NotFound(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()

	_, _, err := runCommand([]string{"scanner", "remove", "nonexistent"})
	if err == nil {
		t.Fatal("expected error for non-existent scanner, got nil")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestRootHelp_IncludesScannerCommands(t *testing.T) {
	// Reset global store to nil to skip initialization
	oldStore := globalStore
	globalStore = nil
	defer func() { globalStore = oldStore }()

	stdout, _, _ := runCommand([]string{"--help"})

	expectedElements := []string{
		"scanner",
		"scan",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in root help output, got: %s", elem, stdout)
		}
	}
}
