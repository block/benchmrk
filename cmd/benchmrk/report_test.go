package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetReportFlags() {
	reportCmd.Flags().Set("format", "md")
	reportCmd.Flags().Set("output", "")
}

func TestReport_DefaultMarkdownToStdout(t *testing.T) {
	_, _, _, _, _, cleanup := setupAnalysisTestEnv(t)
	defer cleanup()
	defer resetReportFlags()

	stdout, _, err := runCommand([]string{"report", "1"})
	if err != nil {
		t.Fatalf("report command failed: %v", err)
	}

	expectedElements := []string{
		"# Benchmark Report:",
		"## Experiment",
		"## Summary",
		"## Scanner Results",
		"scanner-a",
		"scanner-b",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected markdown output to contain %q, got: %s", elem, stdout)
		}
	}
}

func TestReport_JSONFormat(t *testing.T) {
	_, _, _, _, _, cleanup := setupAnalysisTestEnv(t)
	defer cleanup()
	defer resetReportFlags()

	stdout, _, err := runCommand([]string{"report", "1", "--format", "json"})
	if err != nil {
		t.Fatalf("report command failed: %v", err)
	}

	expectedElements := []string{
		`"title"`,
		`"experiment"`,
		`"scanners"`,
		`"by_scanner"`,
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected JSON output to contain %q, got: %s", elem, stdout)
		}
	}
}

func TestReport_MultipleFormatsGenerateFiles(t *testing.T) {
	_, _, _, _, _, cleanup := setupAnalysisTestEnv(t)
	defer cleanup()
	defer resetReportFlags()

	outputDir := filepath.Join(t.TempDir(), "reports")

	_, _, err := runCommand([]string{"report", "1", "--format", "md,csv,html", "--output", outputDir})
	if err != nil {
		t.Fatalf("report command failed: %v", err)
	}

	expectedFiles := []string{"report.md", "report.csv", "report.html"}
	for _, filename := range expectedFiles {
		path := filepath.Join(outputDir, filename)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist", path)
		}
	}
}

func TestReport_OutputDirectoryControlsOutput(t *testing.T) {
	_, _, _, _, _, cleanup := setupAnalysisTestEnv(t)
	defer cleanup()
	defer resetReportFlags()

	outputDir := filepath.Join(t.TempDir(), "custom-reports")

	_, _, err := runCommand([]string{"report", "1", "--format", "json", "--output", outputDir})
	if err != nil {
		t.Fatalf("report command failed: %v", err)
	}

	path := filepath.Join(outputDir, "report.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected file %s to exist", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	if !strings.Contains(string(content), `"title"`) {
		t.Errorf("expected JSON content in file, got: %s", string(content))
	}
}

func TestReport_InvalidFormatReturnsError(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetReportFlags()

	_, _, err := runCommand([]string{"report", "1", "--format", "invalid"})
	if err == nil {
		t.Fatal("expected error for invalid format, got nil")
	}

	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("expected error about invalid format, got: %v", err)
	}
}

func TestReport_NonExistentExperimentReturnsError(t *testing.T) {
	_, cleanup := setupTestEnv(t)
	defer cleanup()
	defer resetReportFlags()

	_, _, err := runCommand([]string{"report", "999"})
	if err == nil {
		t.Fatal("expected error for non-existent experiment, got nil")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "not found") && !strings.Contains(errStr, "experiment") {
		t.Errorf("expected error about experiment not found, got: %v", err)
	}
}

func TestReportHelp_ShowsUsage(t *testing.T) {
	oldStore := globalStore
	globalStore = nil
	defer func() { globalStore = oldStore }()
	defer resetReportFlags()

	stdout, _, _ := runCommand([]string{"report", "--help"})

	expectedElements := []string{
		"report",
		"experiment-id",
		"--format",
		"--output",
		"md",
		"json",
		"csv",
		"html",
		"sarif",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(stdout, elem) {
			t.Errorf("expected %q in help output, got: %s", elem, stdout)
		}
	}
}

func TestParseFormats_ValidFormats(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"md", []string{"md"}},
		{"json", []string{"json"}},
		{"csv", []string{"csv"}},
		{"html", []string{"html"}},
		{"sarif", []string{"sarif"}},
		{"markdown", []string{"md"}},
		{"md,json", []string{"md", "json"}},
		{"md,csv,html", []string{"md", "csv", "html"}},
		{"MD,JSON", []string{"md", "json"}},
		{" md , json ", []string{"md", "json"}},
	}

	for _, tc := range tests {
		formats, err := parseFormats(tc.input)
		if err != nil {
			t.Errorf("parseFormats(%q) returned error: %v", tc.input, err)
			continue
		}
		if len(formats) != len(tc.expected) {
			t.Errorf("parseFormats(%q) = %v, expected %v", tc.input, formats, tc.expected)
			continue
		}
		for i, f := range formats {
			if f != tc.expected[i] {
				t.Errorf("parseFormats(%q)[%d] = %q, expected %q", tc.input, i, f, tc.expected[i])
			}
		}
	}
}

func TestParseFormats_InvalidFormat(t *testing.T) {
	_, err := parseFormats("pdf")
	if err == nil {
		t.Fatal("expected error for invalid format, got nil")
	}
	if !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("expected error about invalid format, got: %v", err)
	}
}

func TestParseFormats_EmptyDefaults(t *testing.T) {
	formats, err := parseFormats("")
	if err != nil {
		t.Fatalf("parseFormats(\"\") returned error: %v", err)
	}
	if len(formats) != 1 || formats[0] != "md" {
		t.Errorf("parseFormats(\"\") = %v, expected [md]", formats)
	}
}
