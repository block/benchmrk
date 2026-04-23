package corpus

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

	// Create JSON file
	jsonData := `[
		{"file_path": "auth.go", "start_line": 10, "cwe_id": "CWE-89", "category": "sql-injection", "severity": "high", "description": "SQL injection"},
		{"file_path": "user.go", "start_line": 20, "end_line": 25, "cwe_id": "CWE-79", "category": "xss", "severity": "medium"}
	]`
	jsonFile := filepath.Join(t.TempDir(), "annotations.json")
	if err := os.WriteFile(jsonFile, []byte(jsonData), 0644); err != nil {
		t.Fatalf("write json file: %v", err)
	}

	count, err := svc.ImportAnnotations(ctx, "import-test", jsonFile)
	if err != nil {
		t.Fatalf("ImportAnnotations: %v", err)
	}

	if count != 2 {
		t.Errorf("expected 2 imported, got %d", count)
	}

	// Verify they exist
	annotations, err := svc.ListAnnotations(ctx, "import-test")
	if err != nil {
		t.Fatalf("ListAnnotations: %v", err)
	}

	if len(annotations) != 2 {
		t.Errorf("expected 2 annotations after import, got %d", len(annotations))
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

	// Add some annotations
	endLine := 15
	_, err = svc.AddAnnotation(ctx, "export-test", "auth.go", 10, &endLine, "CWE-89", "sql-injection", "high", "SQL injection", "valid")
	if err != nil {
		t.Fatalf("AddAnnotation: %v", err)
	}

	data, err := svc.ExportAnnotations(ctx, "export-test")
	if err != nil {
		t.Fatalf("ExportAnnotations: %v", err)
	}

	// Verify it's valid JSON
	var result []AnnotationJSON
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 annotation in export, got %d", len(result))
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

	// Original data
	original := []AnnotationJSON{
		{FilePath: "auth.go", StartLine: 10, EndLine: intPtr(15), CWEID: "CWE-89", Category: "sql-injection", Severity: "high", Description: "SQL injection in login"},
		{FilePath: "user.go", StartLine: 20, CWEID: "CWE-79", Category: "xss", Severity: "medium", Description: ""},
	}

	// Write to file
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jsonFile := filepath.Join(t.TempDir(), "roundtrip.json")
	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	// Import
	count, err := svc.ImportAnnotations(ctx, "roundtrip-test", jsonFile)
	if err != nil {
		t.Fatalf("ImportAnnotations: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 imported, got %d", count)
	}

	// Export
	exported, err := svc.ExportAnnotations(ctx, "roundtrip-test")
	if err != nil {
		t.Fatalf("ExportAnnotations: %v", err)
	}

	// Parse exported
	var result []AnnotationJSON
	if err := json.Unmarshal(exported, &result); err != nil {
		t.Fatalf("unmarshal exported: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 exported, got %d", len(result))
	}

	// Verify fields match
	for i, r := range result {
		o := original[i]
		if r.FilePath != o.FilePath {
			t.Errorf("[%d] file path: expected %q, got %q", i, o.FilePath, r.FilePath)
		}
		if r.StartLine != o.StartLine {
			t.Errorf("[%d] start line: expected %d, got %d", i, o.StartLine, r.StartLine)
		}
		if (r.EndLine == nil) != (o.EndLine == nil) {
			t.Errorf("[%d] end line mismatch: expected %v, got %v", i, o.EndLine, r.EndLine)
		} else if r.EndLine != nil && o.EndLine != nil && *r.EndLine != *o.EndLine {
			t.Errorf("[%d] end line: expected %d, got %d", i, *o.EndLine, *r.EndLine)
		}
		if r.CWEID != o.CWEID {
			t.Errorf("[%d] CWE ID: expected %q, got %q", i, o.CWEID, r.CWEID)
		}
		if r.Category != o.Category {
			t.Errorf("[%d] category: expected %q, got %q", i, o.Category, r.Category)
		}
		if r.Severity != o.Severity {
			t.Errorf("[%d] severity: expected %q, got %q", i, o.Severity, r.Severity)
		}
		if r.Description != o.Description {
			t.Errorf("[%d] description: expected %q, got %q", i, o.Description, r.Description)
		}
	}
}

func TestImportAnnotations_EmptyArray_Succeeds(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})
	ctx := context.Background()
	_, err := svc.AddProject(ctx, "empty-import", testDir, "go", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// Create empty JSON array file
	jsonFile := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(jsonFile, []byte("[]"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	count, err := svc.ImportAnnotations(ctx, "empty-import", jsonFile)
	if err != nil {
		t.Fatalf("ImportAnnotations: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 imported for empty array, got %d", count)
	}
}

func TestExportAnnotations_NoAnnotations_ReturnsEmptyArray(t *testing.T) {
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

	// Should be an empty JSON array
	if string(data) != "[]" {
		t.Errorf("expected empty JSON array '[]', got %q", string(data))
	}
}

func intPtr(i int) *int {
	return &i
}
