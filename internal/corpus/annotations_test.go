package corpus

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddAnnotation_CreatesWithCorrectFields(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	// Create a project first
	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "test-project", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	endLine := 10
	annotation, err := svc.AddAnnotation(ctx, "test-project", "src/auth.go", 5, &endLine, "CWE-89", "sql-injection", "high", "SQL injection in login", "valid")
	if err != nil {
		t.Fatalf("AddAnnotation: %v", err)
	}

	if annotation.FilePath != "src/auth.go" {
		t.Errorf("expected file path 'src/auth.go', got %q", annotation.FilePath)
	}
	if annotation.StartLine != 5 {
		t.Errorf("expected start line 5, got %d", annotation.StartLine)
	}
	if !annotation.EndLine.Valid || annotation.EndLine.Int64 != 10 {
		t.Errorf("expected end line 10, got %v", annotation.EndLine)
	}
	if !annotation.CWEID.Valid || annotation.CWEID.String != "CWE-89" {
		t.Errorf("expected CWE-89, got %v", annotation.CWEID)
	}
	if annotation.Category != "sql-injection" {
		t.Errorf("expected category 'sql-injection', got %q", annotation.Category)
	}
	if annotation.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", annotation.Severity)
	}
	if !annotation.Description.Valid || annotation.Description.String != "SQL injection in login" {
		t.Errorf("expected description 'SQL injection in login', got %v", annotation.Description)
	}
}

func TestAddAnnotation_NonExistentProject_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	ctx := context.Background()
	_, err := svc.AddAnnotation(ctx, "nonexistent", "file.go", 1, nil, "CWE-79", "xss", "medium", "", "valid")
	if err != ErrProjectNotFound {
		t.Errorf("expected ErrProjectNotFound, got %v", err)
	}
}

func TestAddAnnotation_InvalidSeverity_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "test-project", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	_, err = svc.AddAnnotation(ctx, "test-project", "file.go", 1, nil, "CWE-79", "xss", "invalid-severity", "", "valid")
	if err != ErrInvalidSeverity {
		t.Errorf("expected ErrInvalidSeverity, got %v", err)
	}
}

func TestListAnnotations_ReturnsAnnotationsForProject(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir1 := createTestDir(t, map[string]string{"main.go": "package main"})
	testDir2 := createTestDir(t, map[string]string{"app.py": "print('hi')"})

	ctx := context.Background()
	_, err := svc.AddProject(ctx, "project-a", testDir1, "go", "")
	if err != nil {
		t.Fatalf("AddProject a: %v", err)
	}
	_, err = svc.AddProject(ctx, "project-b", testDir2, "python", "")
	if err != nil {
		t.Fatalf("AddProject b: %v", err)
	}

	// Add annotations to project-a
	_, err = svc.AddAnnotation(ctx, "project-a", "auth.go", 10, nil, "CWE-89", "sql-injection", "high", "", "valid")
	if err != nil {
		t.Fatalf("AddAnnotation 1: %v", err)
	}
	_, err = svc.AddAnnotation(ctx, "project-a", "user.go", 20, nil, "CWE-79", "xss", "medium", "", "valid")
	if err != nil {
		t.Fatalf("AddAnnotation 2: %v", err)
	}

	// Add annotation to project-b
	_, err = svc.AddAnnotation(ctx, "project-b", "app.py", 5, nil, "CWE-22", "path-traversal", "low", "", "valid")
	if err != nil {
		t.Fatalf("AddAnnotation 3: %v", err)
	}

	// List annotations for project-a only
	annotations, err := svc.ListAnnotations(ctx, "project-a")
	if err != nil {
		t.Fatalf("ListAnnotations: %v", err)
	}

	if len(annotations) != 2 {
		t.Errorf("expected 2 annotations for project-a, got %d", len(annotations))
	}
}

func TestImportAnnotations_ParsesJSONAndInserts(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "import-test", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// Vulnerability envelope — the only shape accepted by the importer.
	jsonData := `{
		"vulnerabilities": [
			{
				"name": "auth-sqli",
				"description": "SQL injection",
				"cwes": ["CWE-89"],
				"evidence": [{"file": "auth.go", "line": 10, "category": "sql-injection", "severity": "high"}]
			},
			{
				"name": "user-xss",
				"cwes": ["CWE-79"],
				"evidence": [{"file": "user.go", "line": 20, "end": 25, "category": "xss", "severity": "medium"}]
			}
		]
	}`
	jsonFile := filepath.Join(t.TempDir(), "annotations.json")
	if err := os.WriteFile(jsonFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("write json file: %v", err)
	}

	count, err := svc.ImportAnnotations(ctx, "import-test", jsonFile)
	if err != nil {
		t.Fatalf("ImportAnnotations: %v", err)
	}

	// Count is evidence rows — one per vuln here.
	if count != 2 {
		t.Errorf("expected 2 evidence rows imported, got %d", count)
	}

	// Verify via the compat shim (each evidence row surfaces as one Annotation).
	annotations, err := svc.ListAnnotations(ctx, "import-test")
	if err != nil {
		t.Fatalf("ListAnnotations: %v", err)
	}

	if len(annotations) != 2 {
		t.Errorf("expected 2 annotations after import, got %d", len(annotations))
	}
}

func TestImportAnnotations_NonObjectShape_Rejected(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "shape-reject", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// Anything that isn't the {"vulnerabilities": [...]} envelope must
	// be rejected at the shape guard with an actionable error.
	jsonData := `[{"file": "auth.go", "line": 10}]`
	jsonFile := filepath.Join(t.TempDir(), "wrong-shape.json")
	if err := os.WriteFile(jsonFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("write json file: %v", err)
	}

	_, err = svc.ImportAnnotations(ctx, "shape-reject", jsonFile)
	if err == nil {
		t.Fatal("expected error for non-object shape, got nil")
	}
	if !strings.Contains(err.Error(), "{") || !strings.Contains(err.Error(), "vulnerabilities") {
		t.Errorf("error should mention the required '{\"vulnerabilities\": ...}' shape, got: %v", err)
	}
}

func TestImportAnnotations_MalformedJSON_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "import-test", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// Create malformed JSON file
	jsonFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(jsonFile, []byte("{not valid json"), 0644); err != nil {
		t.Fatalf("write json file: %v", err)
	}

	_, err = svc.ImportAnnotations(ctx, "import-test", jsonFile)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestExportAnnotations_ProducesValidJSON(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "export-test", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// AddAnnotation creates a solo vulnerability with one evidence
	// row — export should reflect it as a single-entry envelope.
	endLine := 15
	_, err = svc.AddAnnotation(ctx, "export-test", "auth.go", 10, &endLine, "CWE-89", "sql-injection", "high", "SQL injection", "valid")
	if err != nil {
		t.Fatalf("AddAnnotation: %v", err)
	}

	data, err := svc.ExportAnnotations(ctx, "export-test")
	if err != nil {
		t.Fatalf("ExportAnnotations: %v", err)
	}

	// New export format: {"vulnerabilities": [...]} envelope.
	var result vulnFileEnvelope
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability in export, got %d", len(result.Vulnerabilities))
	}
	v := result.Vulnerabilities[0]
	if len(v.Evidence) != 1 {
		t.Errorf("expected 1 evidence row, got %d", len(v.Evidence))
	}
	if v.Evidence[0].File != "auth.go" || v.Evidence[0].Line != 10 {
		t.Errorf("evidence location mismatch: got %s:%d", v.Evidence[0].File, v.Evidence[0].Line)
	}
	if len(v.CWEs) != 1 || v.CWEs[0] != "CWE-89" {
		t.Errorf("expected CWE-89, got %v", v.CWEs)
	}
}

func TestImportExport_RoundTrip_PreservesFields(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "roundtrip-test", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// Round-trip the vulnerability envelope. Exercises every field a
	// lossy per-evidence export would drop: the CWE set (>1 per vuln),
	// the annotator list, criticality, and multi-evidence vulns.
	original := vulnFileEnvelope{
		Vulnerabilities: []VulnerabilityJSON{
			{
				Name:        "login-sqli",
				Description: "SQL injection in login",
				Criticality: "must",
				Status:      "valid",
				CWEs:        []string{"CWE-89", "CWE-564"},
				AnnotatedBy: []string{"alice", "bob"},
				Evidence: []EvidenceJSON{
					{File: "auth.go", Line: 10, End: intPtr(15), Role: "sink", Category: "sql-injection", Severity: "high"},
				},
			},
			{
				Name:        "task-idor",
				Description: "Tasks resource lacks ownership checks on all handlers",
				Criticality: "should",
				Status:      "valid",
				CWEs:        []string{"CWE-639", "CWE-862"},
				AnnotatedBy: []string{"carol"},
				Evidence: []EvidenceJSON{
					{File: "routes/api.js", Line: 42, Role: "sink", Category: "broken-access-control", Severity: "high"},
					{File: "routes/tasks.js", Line: 88, End: intPtr(94), Role: "sink", Category: "broken-access-control", Severity: "high"},
				},
			},
		},
	}

	// Write file in new-format envelope
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jsonFile := filepath.Join(t.TempDir(), "roundtrip.json")
	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Import — count is evidence-row count on the new-format path
	count, err := svc.ImportAnnotations(ctx, "roundtrip-test", jsonFile)
	if err != nil {
		t.Fatalf("ImportAnnotations: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 evidence rows imported, got %d", count)
	}

	// Export
	exported, err := svc.ExportAnnotations(ctx, "roundtrip-test")
	if err != nil {
		t.Fatalf("ExportAnnotations: %v", err)
	}

	var result vulnFileEnvelope
	if err := json.Unmarshal(exported, &result); err != nil {
		t.Fatalf("unmarshal exported: %v", err)
	}

	if len(result.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulns exported, got %d", len(result.Vulnerabilities))
	}

	// Index by name — ListVulnerabilitiesByProject orders by ID, which
	// tracks insertion order, but matching by name is clearer and more
	// robust to future sort changes.
	got := map[string]VulnerabilityJSON{}
	for _, v := range result.Vulnerabilities {
		got[v.Name] = v
	}

	for _, want := range original.Vulnerabilities {
		g, ok := got[want.Name]
		if !ok {
			t.Errorf("vuln %q missing from export", want.Name)
			continue
		}
		if g.Description != want.Description {
			t.Errorf("%s: description = %q, want %q", want.Name, g.Description, want.Description)
		}
		if g.Criticality != want.Criticality {
			t.Errorf("%s: criticality = %q, want %q", want.Name, g.Criticality, want.Criticality)
		}
		if g.Status != want.Status {
			t.Errorf("%s: status = %q, want %q", want.Name, g.Status, want.Status)
		}
		if !sameStringSet(g.CWEs, want.CWEs) {
			t.Errorf("%s: CWEs = %v, want %v", want.Name, g.CWEs, want.CWEs)
		}
		if !sameStringSet(g.AnnotatedBy, want.AnnotatedBy) {
			t.Errorf("%s: AnnotatedBy = %v, want %v", want.Name, g.AnnotatedBy, want.AnnotatedBy)
		}
		if len(g.Evidence) != len(want.Evidence) {
			t.Errorf("%s: evidence count = %d, want %d", want.Name, len(g.Evidence), len(want.Evidence))
			continue
		}
		// Evidence is emitted in ListEvidenceByProject's ORDER BY
		// file_path, start_line. Sort expected the same way via a
		// name-keyed lookup.
		wantByKey := map[string]EvidenceJSON{}
		for _, e := range want.Evidence {
			wantByKey[e.File] = e
		}
		for _, g := range g.Evidence {
			w, ok := wantByKey[g.File]
			if !ok {
				t.Errorf("%s: unexpected evidence file %q", want.Name, g.File)
				continue
			}
			if g.Line != w.Line {
				t.Errorf("%s/%s: line = %d, want %d", want.Name, g.File, g.Line, w.Line)
			}
			if (g.End == nil) != (w.End == nil) {
				t.Errorf("%s/%s: end nil mismatch: got %v want %v", want.Name, g.File, g.End, w.End)
			} else if g.End != nil && *g.End != *w.End {
				t.Errorf("%s/%s: end = %d, want %d", want.Name, g.File, *g.End, *w.End)
			}
			if g.Role != w.Role {
				t.Errorf("%s/%s: role = %q, want %q", want.Name, g.File, g.Role, w.Role)
			}
			if g.Category != w.Category {
				t.Errorf("%s/%s: category = %q, want %q", want.Name, g.File, g.Category, w.Category)
			}
			if g.Severity != w.Severity {
				t.Errorf("%s/%s: severity = %q, want %q", want.Name, g.File, g.Severity, w.Severity)
			}
		}
	}
}

// sameStringSet compares two slices as sets (order-independent).
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestImportAnnotations_EmptyEnvelope_Rejected(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "empty-import", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// An envelope with no vulnerabilities is an error — a no-op
	// "import" is almost always a mistake the user wants to hear about.
	jsonFile := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(jsonFile, []byte(`{"vulnerabilities": []}`), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	_, err = svc.ImportAnnotations(ctx, "empty-import", jsonFile)
	if err == nil {
		t.Error("expected error for empty vulnerabilities array, got nil")
	}
}

func TestExportAnnotations_NoAnnotations_ReturnsEmptyEnvelope(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "empty-export", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	data, err := svc.ExportAnnotations(ctx, "empty-export")
	if err != nil {
		t.Fatalf("ExportAnnotations: %v", err)
	}

	// Empty export is still the envelope with an empty
	// vulnerabilities array — it must still parse as the canonical
	// shape so that re-importing an empty file fails the way it would
	// for any other wrong-shape file, not silently succeed.
	var env vulnFileEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(env.Vulnerabilities))
	}
}

func intPtr(i int) *int {
	return &i
}
