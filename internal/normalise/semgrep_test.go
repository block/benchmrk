package normalise

import (
	"strings"
	"testing"
)

var semgrepValidJSON = `{
	"results": [
		{
			"check_id": "python.flask.security.injection.sql-injection",
			"path": "app/db.py",
			"start": {"line": 42, "col": 5, "offset": 1234},
			"end": {"line": 42, "col": 40, "offset": 1269},
			"extra": {
				"message": "Detected SQL injection vulnerability",
				"severity": "ERROR",
				"metadata": {
					"cwe": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"],
					"confidence": "HIGH",
					"category": "security"
				},
				"lines": "    cursor.execute(query % user_input)"
			}
		},
		{
			"check_id": "python.flask.security.xss",
			"path": "app/views.py",
			"start": {"line": 100, "col": 1},
			"end": {"line": 105, "col": 20},
			"extra": {
				"message": "Potential XSS vulnerability",
				"severity": "WARNING",
				"metadata": {
					"cwe": "CWE-79",
					"confidence": "MEDIUM",
					"category": "security"
				},
				"lines": "    return render(user_input)"
			}
		}
	],
	"errors": [],
	"version": "1.50.0"
}`

func TestSemgrepConverter_ValidOutput(t *testing.T) {
	conv := &SemgrepConverter{}
	report, err := conv.Convert(strings.NewReader(semgrepValidJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Errorf("expected SARIF version '2.1.0', got %q", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != "Semgrep" {
		t.Errorf("expected tool name 'Semgrep', got %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.50.0" {
		t.Errorf("expected tool version '1.50.0', got %q", run.Tool.Driver.Version)
	}

	// Check results
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}

	r1 := run.Results[0]
	if r1.RuleID != "python.flask.security.injection.sql-injection" {
		t.Errorf("r1.RuleID = %q", r1.RuleID)
	}
	if r1.Level != "error" {
		t.Errorf("r1.Level = %q, want 'error'", r1.Level)
	}
	if r1.Message.Text != "Detected SQL injection vulnerability" {
		t.Errorf("r1.Message = %q", r1.Message.Text)
	}
	if len(r1.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r1.Locations))
	}
	loc := r1.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "app/db.py" {
		t.Errorf("expected URI 'app/db.py', got %q", loc.ArtifactLocation.URI)
	}
	if *loc.Region.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", *loc.Region.StartLine)
	}
	if *loc.Region.EndLine != 42 {
		t.Errorf("expected end line 42, got %d", *loc.Region.EndLine)
	}
	if loc.Region.Snippet.Text != "    cursor.execute(query % user_input)" {
		t.Errorf("snippet = %q", loc.Region.Snippet.Text)
	}

	r2 := run.Results[1]
	if r2.Level != "warning" {
		t.Errorf("r2.Level = %q, want 'warning'", r2.Level)
	}

	// Check rules were built
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestSemgrepConverter_EmptyResults(t *testing.T) {
	input := `{"results": [], "errors": [], "version": "1.50.0"}`

	conv := &SemgrepConverter{}
	report, err := conv.Convert(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(report.Runs[0].Results))
	}
	if len(report.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(report.Runs[0].Tool.Driver.Rules))
	}
}

func TestSemgrepConverter_CWEExtraction(t *testing.T) {
	tests := []struct {
		name     string
		cwe      interface{}
		expected string
	}{
		{"string CWE-89", "CWE-89", "CWE-89"},
		{"string with description", "CWE-89: SQL Injection", "CWE-89"},
		{"array single", []interface{}{"CWE-79: XSS"}, "CWE-79"},
		{"array multiple takes first", []interface{}{"CWE-89: SQLi", "CWE-79: XSS"}, "CWE-89"},
		{"empty array", []interface{}{}, ""},
		{"nil", nil, ""},
		{"non-CWE string", "not-a-cwe", ""},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSemgrepCWE(tt.cwe)
			if got != tt.expected {
				t.Errorf("extractSemgrepCWE(%v) = %q, want %q", tt.cwe, got, tt.expected)
			}
		})
	}
}

func TestSemgrepSeverityToSARIF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ERROR", "error"},
		{"error", "error"},
		{"WARNING", "warning"},
		{"warning", "warning"},
		{"INFO", "note"},
		{"info", "note"},
		{"UNKNOWN", "warning"},
		{"", "warning"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := semgrepSeverityToSARIF(tt.input)
			if got != tt.expected {
				t.Errorf("semgrepSeverityToSARIF(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractCWEID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CWE-89", "CWE-89"},
		{"CWE-89: SQL Injection", "CWE-89"},
		{"cwe-79", "cwe-79"},
		{"CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "CWE-79"},
		{"not-a-cwe", ""},
		{"", ""},
		{"  CWE-100  ", "CWE-100"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractCWEID(tt.input)
			if got != tt.expected {
				t.Errorf("extractCWEID(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSemgrepConverter_InvalidJSON(t *testing.T) {
	conv := &SemgrepConverter{}
	_, err := conv.Convert(strings.NewReader("{invalid"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse semgrep JSON") {
		t.Errorf("expected 'parse semgrep JSON' error, got: %v", err)
	}
}

func TestSemgrepConverter_MissingOptionalFields(t *testing.T) {
	input := `{
		"results": [{
			"check_id": "rule-1",
			"path": "file.py",
			"start": {"line": 5},
			"end": {"line": 5},
			"extra": {
				"message": "Finding",
				"severity": "INFO"
			}
		}],
		"version": "1.0.0"
	}`

	conv := &SemgrepConverter{}
	report, err := conv.Convert(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}

	r := report.Runs[0].Results[0]
	if r.Level != "note" {
		t.Errorf("expected level 'note' for INFO severity, got %q", r.Level)
	}

	// Rule should have no CWE properties since metadata is empty
	rules := report.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Properties != nil {
		t.Errorf("expected nil Properties when no CWE, got %+v", rules[0].Properties)
	}
}

func TestSemgrepConverter_DuplicateCheckIDs(t *testing.T) {
	input := `{
		"results": [
			{
				"check_id": "rule-1",
				"path": "a.py",
				"start": {"line": 1},
				"end": {"line": 1},
				"extra": {"message": "First", "severity": "ERROR"}
			},
			{
				"check_id": "rule-1",
				"path": "b.py",
				"start": {"line": 2},
				"end": {"line": 2},
				"extra": {"message": "Second", "severity": "ERROR"}
			}
		],
		"version": "1.0.0"
	}`

	conv := &SemgrepConverter{}
	report, err := conv.Convert(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 2 results but only 1 unique rule
	if len(report.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(report.Runs[0].Results))
	}
	if len(report.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 rule (deduplicated), got %d", len(report.Runs[0].Tool.Driver.Rules))
	}
}

func TestNewDefaultRegistry_HasSemgrepJSON(t *testing.T) {
	reg := NewDefaultRegistry()

	_, ok := reg.Get("semgrep-json")
	if !ok {
		t.Error("expected 'semgrep-json' converter in default registry")
	}
}
