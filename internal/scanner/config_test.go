package scanner

import (
	"strings"
	"testing"
)

func TestParseScannerConfig_Empty(t *testing.T) {
	cfg, err := ParseScannerConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OutputFormat != "" {
		t.Errorf("expected empty OutputFormat, got %q", cfg.OutputFormat)
	}
	if cfg.OutputFile != "" {
		t.Errorf("expected empty OutputFile, got %q", cfg.OutputFile)
	}
	if len(cfg.Cmd) != 0 {
		t.Errorf("expected empty Cmd, got %v", cfg.Cmd)
	}
	if len(cfg.Entrypoint) != 0 {
		t.Errorf("expected empty Entrypoint, got %v", cfg.Entrypoint)
	}
	if len(cfg.Env) != 0 {
		t.Errorf("expected empty Env, got %v", cfg.Env)
	}
}

func TestParseScannerConfig_Valid(t *testing.T) {
	json := `{
		"cmd": ["semgrep", "--config=auto", "--sarif"],
		"entrypoint": ["/bin/sh", "-c"],
		"env": {"SEMGREP_SEND_METRICS": "off", "EXTRA": "val"},
		"output_format": "semgrep-json",
		"output_file": "results.json"
	}`

	cfg, err := ParseScannerConfig(json)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Cmd) != 3 || cfg.Cmd[0] != "semgrep" {
		t.Errorf("expected Cmd [semgrep --config=auto --sarif], got %v", cfg.Cmd)
	}
	if len(cfg.Entrypoint) != 2 || cfg.Entrypoint[0] != "/bin/sh" {
		t.Errorf("expected Entrypoint [/bin/sh -c], got %v", cfg.Entrypoint)
	}
	if cfg.Env["SEMGREP_SEND_METRICS"] != "off" {
		t.Errorf("expected SEMGREP_SEND_METRICS=off, got %q", cfg.Env["SEMGREP_SEND_METRICS"])
	}
	if cfg.Env["EXTRA"] != "val" {
		t.Errorf("expected EXTRA=val, got %q", cfg.Env["EXTRA"])
	}
	if cfg.OutputFormat != "semgrep-json" {
		t.Errorf("expected OutputFormat 'semgrep-json', got %q", cfg.OutputFormat)
	}
	if cfg.OutputFile != "results.json" {
		t.Errorf("expected OutputFile 'results.json', got %q", cfg.OutputFile)
	}
}

func TestParseScannerConfig_Invalid(t *testing.T) {
	_, err := ParseScannerConfig("{invalid json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse scanner config") {
		t.Errorf("expected 'parse scanner config' in error, got: %v", err)
	}
}

func TestScannerConfig_Merge(t *testing.T) {
	base := ScannerConfig{
		Cmd:          []string{"semgrep", "--sarif"},
		Entrypoint:   []string{"/bin/sh"},
		Env:          map[string]string{"KEY1": "val1", "KEY2": "val2"},
		OutputFormat: "sarif",
		OutputFile:   "results.sarif",
	}

	overrides := ScannerConfig{
		Cmd:          []string{"semgrep", "--json"},
		Env:          map[string]string{"KEY2": "overridden", "KEY3": "val3"},
		OutputFormat: "semgrep-json",
	}

	merged := base.Merge(overrides)

	// Cmd should be overridden
	if len(merged.Cmd) != 2 || merged.Cmd[1] != "--json" {
		t.Errorf("expected Cmd overridden, got %v", merged.Cmd)
	}
	// Entrypoint should be preserved (not overridden with empty)
	if len(merged.Entrypoint) != 1 || merged.Entrypoint[0] != "/bin/sh" {
		t.Errorf("expected Entrypoint preserved, got %v", merged.Entrypoint)
	}
	// Env should be merged
	if merged.Env["KEY1"] != "val1" {
		t.Errorf("expected KEY1 preserved, got %q", merged.Env["KEY1"])
	}
	if merged.Env["KEY2"] != "overridden" {
		t.Errorf("expected KEY2 overridden, got %q", merged.Env["KEY2"])
	}
	if merged.Env["KEY3"] != "val3" {
		t.Errorf("expected KEY3 added, got %q", merged.Env["KEY3"])
	}
	// OutputFormat should be overridden
	if merged.OutputFormat != "semgrep-json" {
		t.Errorf("expected OutputFormat 'semgrep-json', got %q", merged.OutputFormat)
	}
	// OutputFile should be preserved (not overridden with empty)
	if merged.OutputFile != "results.sarif" {
		t.Errorf("expected OutputFile preserved, got %q", merged.OutputFile)
	}
}

func TestScannerConfig_Merge_EmptyOverride(t *testing.T) {
	base := ScannerConfig{
		Cmd:          []string{"tool", "--arg"},
		OutputFormat: "sarif",
		OutputFile:   "results.sarif",
		Env:          map[string]string{"KEY": "val"},
	}

	merged := base.Merge(ScannerConfig{})

	if len(merged.Cmd) != 2 || merged.Cmd[0] != "tool" {
		t.Errorf("expected Cmd preserved, got %v", merged.Cmd)
	}
	if merged.OutputFormat != "sarif" {
		t.Errorf("expected OutputFormat preserved, got %q", merged.OutputFormat)
	}
	if merged.OutputFile != "results.sarif" {
		t.Errorf("expected OutputFile preserved, got %q", merged.OutputFile)
	}
	if merged.Env["KEY"] != "val" {
		t.Errorf("expected Env preserved, got %v", merged.Env)
	}
}

func TestScannerConfig_Merge_NilBaseEnv(t *testing.T) {
	base := ScannerConfig{}
	overrides := ScannerConfig{
		Env: map[string]string{"KEY": "val"},
	}

	merged := base.Merge(overrides)

	if merged.Env["KEY"] != "val" {
		t.Errorf("expected Env added to nil base, got %v", merged.Env)
	}
}

func TestScannerConfig_ResolvedOutputFile(t *testing.T) {
	tests := []struct {
		name     string
		cfg      ScannerConfig
		expected string
	}{
		{"default empty config", ScannerConfig{}, "results.sarif"},
		{"explicit sarif format", ScannerConfig{OutputFormat: "sarif"}, "results.sarif"},
		{"semgrep-json format", ScannerConfig{OutputFormat: "semgrep-json"}, "results.json"},
		{"unknown format", ScannerConfig{OutputFormat: "custom-xml"}, "results.json"},
		{"explicit output file overrides format", ScannerConfig{OutputFormat: "semgrep-json", OutputFile: "custom.out"}, "custom.out"},
		{"explicit output file with empty format", ScannerConfig{OutputFile: "my-results.sarif"}, "my-results.sarif"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.ResolvedOutputFile()
			if got != tt.expected {
				t.Errorf("ResolvedOutputFile() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestScannerConfig_ResolvedOutputFormat(t *testing.T) {
	tests := []struct {
		name     string
		cfg      ScannerConfig
		expected string
	}{
		{"default empty", ScannerConfig{}, "sarif"},
		{"explicit sarif", ScannerConfig{OutputFormat: "sarif"}, "sarif"},
		{"semgrep-json", ScannerConfig{OutputFormat: "semgrep-json"}, "semgrep-json"},
		{"custom", ScannerConfig{OutputFormat: "custom-format"}, "custom-format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.ResolvedOutputFormat()
			if got != tt.expected {
				t.Errorf("ResolvedOutputFormat() = %q, want %q", got, tt.expected)
			}
		})
	}
}
