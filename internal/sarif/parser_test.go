package sarif

import (
	"strings"
	"testing"
)

var validSARIF = `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Semgrep",
          "version": "1.0.0",
          "rules": [
            {
              "id": "python.flask.security.injection.sql-injection",
              "name": "sql-injection",
              "shortDescription": { "text": "SQL Injection vulnerability" },
              "properties": {
                "tags": ["CWE-89", "security"],
                "precision": "high"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "python.flask.security.xss",
              "name": "xss",
              "shortDescription": { "text": "XSS vulnerability" },
              "properties": {
                "cwe": "CWE-79"
              },
              "defaultConfiguration": {
                "level": "warning"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.flask.security.injection.sql-injection",
          "level": "error",
          "message": { "text": "Detected SQL injection vulnerability" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/db.py" },
                "region": {
                  "startLine": 42,
                  "endLine": 45,
                  "snippet": { "text": "cursor.execute(query % user_input)" }
                }
              }
            }
          ]
        },
        {
          "ruleId": "python.flask.security.xss",
          "level": "warning",
          "message": { "text": "Potential XSS vulnerability" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/views.py" },
                "region": {
                  "startLine": 100
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`

var emptySARIF = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Semgrep",
          "version": "1.0.0"
        }
      },
      "results": []
    }
  ]
}`

var noResultsSARIF = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CodeQL"
        }
      }
    }
  ]
}`

var malformedJSON = `{ "version": "2.1.0", "runs": [ { tool: `

var missingOptionalFieldsSARIF = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Scanner"
        }
      },
      "results": [
        {
          "ruleId": "rule-1",
          "message": { "text": "Finding without optional fields" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "file.js" },
                "region": {
                  "startLine": 10
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`

func TestParse_ValidSARIF(t *testing.T) {
	report, err := Parse(strings.NewReader(validSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("Parse() returned nil report")
	}
	if report.Version != "2.1.0" {
		t.Errorf("Version = %q, want %q", report.Version, "2.1.0")
	}
	if len(report.Runs) != 1 {
		t.Errorf("len(Runs) = %d, want 1", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 2 {
		t.Errorf("len(Results) = %d, want 2", len(report.Runs[0].Results))
	}
}

func TestParse_EmptyResults(t *testing.T) {
	report, err := Parse(strings.NewReader(emptySARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(report.Runs[0].Results) != 0 {
		t.Errorf("len(Results) = %d, want 0", len(report.Runs[0].Results))
	}
}

func TestParse_NoResults(t *testing.T) {
	report, err := Parse(strings.NewReader(noResultsSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if report.Runs[0].Results != nil && len(report.Runs[0].Results) != 0 {
		t.Errorf("Results should be empty or nil, got %d", len(report.Runs[0].Results))
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	_, err := Parse(strings.NewReader(malformedJSON))
	if err == nil {
		t.Error("Parse() expected error for malformed JSON, got nil")
	}
}

func TestParse_MissingOptionalFields(t *testing.T) {
	report, err := Parse(strings.NewReader(missingOptionalFieldsSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(report.Runs[0].Results) != 1 {
		t.Errorf("len(Results) = %d, want 1", len(report.Runs[0].Results))
	}
}

func TestExtractFindings_ValidSARIF(t *testing.T) {
	report, err := Parse(strings.NewReader(validSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	findings, err := ExtractFindings(report)
	if err != nil {
		t.Fatalf("ExtractFindings() unexpected error: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}

	// Check first finding
	f1 := findings[0]
	if f1.RuleID != "python.flask.security.injection.sql-injection" {
		t.Errorf("f1.RuleID = %q", f1.RuleID)
	}
	if f1.FilePath != "app/db.py" {
		t.Errorf("f1.FilePath = %q, want app/db.py", f1.FilePath)
	}
	if f1.StartLine != 42 {
		t.Errorf("f1.StartLine = %d, want 42", f1.StartLine)
	}
	if f1.EndLine != 45 {
		t.Errorf("f1.EndLine = %d, want 45", f1.EndLine)
	}
	if f1.CWE != "CWE-89" {
		t.Errorf("f1.CWE = %q, want CWE-89", f1.CWE)
	}
	if f1.Severity != "high" {
		t.Errorf("f1.Severity = %q, want high", f1.Severity)
	}
	if f1.Snippet != "cursor.execute(query % user_input)" {
		t.Errorf("f1.Snippet = %q", f1.Snippet)
	}

	// Check second finding
	f2 := findings[1]
	if f2.CWE != "CWE-79" {
		t.Errorf("f2.CWE = %q, want CWE-79", f2.CWE)
	}
	if f2.Severity != "medium" {
		t.Errorf("f2.Severity = %q, want medium", f2.Severity)
	}
	if f2.EndLine != f2.StartLine {
		t.Errorf("f2.EndLine should equal StartLine when not specified, got %d != %d", f2.EndLine, f2.StartLine)
	}
}

func TestExtractFindings_EmptyResults(t *testing.T) {
	report, err := Parse(strings.NewReader(emptySARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	findings, err := ExtractFindings(report)
	if err != nil {
		t.Fatalf("ExtractFindings() unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("len(findings) = %d, want 0", len(findings))
	}
}

func TestExtractFindings_NilReport(t *testing.T) {
	_, err := ExtractFindings(nil)
	if err == nil {
		t.Error("ExtractFindings() expected error for nil report, got nil")
	}
}

func TestExtractFindings_MissingOptionalFields(t *testing.T) {
	report, err := Parse(strings.NewReader(missingOptionalFieldsSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	findings, err := ExtractFindings(report)
	if err != nil {
		t.Fatalf("ExtractFindings() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	f := findings[0]
	if f.CWE != "" {
		t.Errorf("CWE should be empty when not specified, got %q", f.CWE)
	}
	if f.Snippet != "" {
		t.Errorf("Snippet should be empty when not specified, got %q", f.Snippet)
	}
	if f.EndLine != f.StartLine {
		t.Errorf("EndLine should equal StartLine when not specified")
	}
}

func TestGenerateFingerprint_Consistent(t *testing.T) {
	f := Finding{
		RuleID:    "sql-injection",
		FilePath:  "app/db.py",
		StartLine: 42,
	}

	fp1 := GenerateFingerprint(f)
	fp2 := GenerateFingerprint(f)

	if fp1 != fp2 {
		t.Errorf("Fingerprints should be consistent, got %q and %q", fp1, fp2)
	}

	if len(fp1) != 64 {
		t.Errorf("SHA256 hex should be 64 chars, got %d", len(fp1))
	}
}

func TestGenerateFingerprint_DifferentForDifferentFindings(t *testing.T) {
	f1 := Finding{
		RuleID:    "sql-injection",
		FilePath:  "app/db.py",
		StartLine: 42,
	}

	f2 := Finding{
		RuleID:    "sql-injection",
		FilePath:  "app/db.py",
		StartLine: 43,
	}

	f3 := Finding{
		RuleID:    "xss",
		FilePath:  "app/db.py",
		StartLine: 42,
	}

	fp1 := GenerateFingerprint(f1)
	fp2 := GenerateFingerprint(f2)
	fp3 := GenerateFingerprint(f3)

	if fp1 == fp2 {
		t.Error("Different start lines should produce different fingerprints")
	}
	if fp1 == fp3 {
		t.Error("Different rule IDs should produce different fingerprints")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"error", "high"},
		{"ERROR", "high"},
		{"warning", "medium"},
		{"WARNING", "medium"},
		{"note", "low"},
		{"NOTE", "low"},
		{"none", "info"},
		{"unknown", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		got := normalizeSeverity(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CWE-89", "CWE-89"},
		{"CWE89", "CWE-89"},
		{"cwe-89", "CWE-89"},
		{"cwe:89", "CWE-89"},
		{"CWE-89: Improper Neutralization of Special Elements", "CWE-89"},
		{"external/cwe/cwe-798", "CWE-798"},
		{"external/cwe/cwe-22", "CWE-22"},
		{"", ""},
		{"invalid", ""},
		{"security", ""},
	}

	for _, tt := range tests {
		got := normalizeCWE(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeCWE(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// Test CWE extraction from relationships (CodeQL/GitHub SARIF format)
func TestExtractFindings_CWEFromRelationships(t *testing.T) {
	relationshipsSARIF := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Scanner",
					"rules": [
						{
							"id": "scanner.sql-injection",
							"properties": {
								"tags": ["security", "external/cwe/cwe-89"]
							},
							"relationships": [
								{
									"target": {
										"id": "CWE-89",
										"toolComponent": {"name": "CWE"}
									},
									"kinds": ["superset"]
								}
							]
						}
					]
				}
			},
			"results": [
				{
					"ruleId": "scanner.sql-injection",
					"level": "error",
					"message": {"text": "SQL injection"},
					"locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 10}}}]
				}
			]
		}]
	}`

	report, err := Parse(strings.NewReader(relationshipsSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	findings, err := ExtractFindings(report)
	if err != nil {
		t.Fatalf("ExtractFindings() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	if findings[0].CWE != "CWE-89" {
		t.Errorf("CWE = %q, want CWE-89 (from relationships)", findings[0].CWE)
	}
}

// Test CWE extraction from tags with description suffix (repointerrogate format)
func TestExtractFindings_CWEFromTagsWithDescription(t *testing.T) {
	tagDescSARIF := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Scanner",
					"rules": [
						{
							"id": "scanner.xss",
							"properties": {
								"tags": ["security", "CWE-79: Improper Neutralization of Input"]
							}
						}
					]
				}
			},
			"results": [
				{
					"ruleId": "scanner.xss",
					"message": {"text": "XSS"},
					"locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.js"}, "region": {"startLine": 5}}}]
				}
			]
		}]
	}`

	report, err := Parse(strings.NewReader(tagDescSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	findings, err := ExtractFindings(report)
	if err != nil {
		t.Fatalf("ExtractFindings() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	if findings[0].CWE != "CWE-79" {
		t.Errorf("CWE = %q, want CWE-79 (from tag with description)", findings[0].CWE)
	}
}

// Test ruleIndex fallback when ruleId is empty but ruleIndex is present
func TestExtractFindings_RuleIndexFallback(t *testing.T) {
	ruleIndexSARIF := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "Scanner",
					"rules": [
						{"id": "rule-zero", "properties": {"cwe": "CWE-100"}},
						{"id": "rule-one", "properties": {"cwe": "CWE-101"}}
					]
				}
			},
			"results": [
				{
					"ruleIndex": 1,
					"message": {"text": "Finding via ruleIndex"},
					"locations": [{"physicalLocation": {"artifactLocation": {"uri": "file.js"}, "region": {"startLine": 5}}}]
				}
			]
		}]
	}`

	report, err := Parse(strings.NewReader(ruleIndexSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	findings, err := ExtractFindings(report)
	if err != nil {
		t.Fatalf("ExtractFindings() unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	f := findings[0]
	if f.RuleID != "rule-one" {
		t.Errorf("RuleID = %q, want 'rule-one' (from ruleIndex)", f.RuleID)
	}
	if f.CWE != "CWE-101" {
		t.Errorf("CWE = %q, want 'CWE-101' (from rule at index 1)", f.CWE)
	}
}

// Test that Parse uses streaming (doesn't panic on large input)
func TestParse_LargeFile(t *testing.T) {
	// Generate a SARIF with many results
	var sb strings.Builder
	sb.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[`)
	for i := 0; i < 10000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"ruleId":"rule-1","message":{"text":"msg"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file.js"},"region":{"startLine":1}}}]}`)
	}
	sb.WriteString(`]}]}`)

	report, err := Parse(strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if len(report.Runs[0].Results) != 10000 {
		t.Errorf("Expected 10000 results, got %d", len(report.Runs[0].Results))
	}
}
