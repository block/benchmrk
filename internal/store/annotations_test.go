package store

import (
	"context"
	"database/sql"
	"testing"
)

func createTestProject(t *testing.T, s *Store) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := s.CreateProject(ctx, &CorpusProject{Name: "test-project", LocalPath: "/tmp/test"})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}
	return id
}

func TestCreateGetAnnotationRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	a := &Annotation{
		ProjectID:   projectID,
		FilePath:    "src/main.go",
		StartLine:   42,
		EndLine:     sql.NullInt64{Int64: 50, Valid: true},
		CWEID:       sql.NullString{String: "CWE-89", Valid: true},
		Category:    "sql-injection",
		Severity:    "high",
		Description: sql.NullString{String: "SQL injection vulnerability", Valid: true},
		Status:      "valid",
		AnnotatedBy: sql.NullString{String: "tester", Valid: true},
	}

	id, err := s.CreateAnnotation(ctx, a)
	if err != nil {
		t.Fatalf("CreateAnnotation() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	got, err := s.GetAnnotation(ctx, id)
	if err != nil {
		t.Fatalf("GetAnnotation() failed: %v", err)
	}

	if got.ProjectID != projectID {
		t.Errorf("ProjectID = %d, want %d", got.ProjectID, projectID)
	}
	if got.FilePath != a.FilePath {
		t.Errorf("FilePath = %q, want %q", got.FilePath, a.FilePath)
	}
	if got.StartLine != a.StartLine {
		t.Errorf("StartLine = %d, want %d", got.StartLine, a.StartLine)
	}
	if got.EndLine != a.EndLine {
		t.Errorf("EndLine = %v, want %v", got.EndLine, a.EndLine)
	}
	if got.CWEID != a.CWEID {
		t.Errorf("CWEID = %v, want %v", got.CWEID, a.CWEID)
	}
	if got.Category != a.Category {
		t.Errorf("Category = %q, want %q", got.Category, a.Category)
	}
	if got.Severity != a.Severity {
		t.Errorf("Severity = %q, want %q", got.Severity, a.Severity)
	}
	if got.Status != a.Status {
		t.Errorf("Status = %q, want %q", got.Status, a.Status)
	}
}

func TestGetAnnotationNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.GetAnnotation(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("GetAnnotation() error = %v, want ErrNotFound", err)
	}
}

func TestListAnnotationsByProject(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	// Create annotations in different files/lines
	for _, fp := range []struct {
		file string
		line int
	}{
		{"b.go", 10},
		{"a.go", 20},
		{"a.go", 5},
	} {
		_, err := s.CreateAnnotation(ctx, &Annotation{
			ProjectID: projectID,
			FilePath:  fp.file,
			StartLine: fp.line,
			Category:  "xss",
			Severity:  "medium",
			Status:    "valid",
		})
		if err != nil {
			t.Fatalf("CreateAnnotation() failed: %v", err)
		}
	}

	annotations, err := s.ListAnnotationsByProject(ctx, projectID)
	if err != nil {
		t.Fatalf("ListAnnotationsByProject() failed: %v", err)
	}
	if len(annotations) != 3 {
		t.Errorf("ListAnnotationsByProject() returned %d annotations, want 3", len(annotations))
	}

	// Verify sorted by file_path, then start_line
	if annotations[0].FilePath != "a.go" || annotations[0].StartLine != 5 {
		t.Errorf("first annotation = %s:%d, want a.go:5", annotations[0].FilePath, annotations[0].StartLine)
	}
	if annotations[1].FilePath != "a.go" || annotations[1].StartLine != 20 {
		t.Errorf("second annotation = %s:%d, want a.go:20", annotations[1].FilePath, annotations[1].StartLine)
	}
	if annotations[2].FilePath != "b.go" || annotations[2].StartLine != 10 {
		t.Errorf("third annotation = %s:%d, want b.go:10", annotations[2].FilePath, annotations[2].StartLine)
	}
}

func TestListAnnotationsByProjectEmptyReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	annotations, err := s.ListAnnotationsByProject(ctx, projectID)
	if err != nil {
		t.Fatalf("ListAnnotationsByProject() failed: %v", err)
	}
	if annotations == nil {
		t.Error("ListAnnotationsByProject() returned nil, want empty slice")
	}
	if len(annotations) != 0 {
		t.Errorf("ListAnnotationsByProject() returned %d annotations, want 0", len(annotations))
	}
}

func TestListAnnotationsByProjectFiltersCorrectly(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Create two projects
	project1, _ := s.CreateProject(ctx, &CorpusProject{Name: "project1", LocalPath: "/tmp/p1"})
	project2, _ := s.CreateProject(ctx, &CorpusProject{Name: "project2", LocalPath: "/tmp/p2"})

	// Add annotations to each project
	s.CreateAnnotation(ctx, &Annotation{ProjectID: project1, FilePath: "p1.go", StartLine: 1, Category: "xss", Severity: "high", Status: "valid"})
	s.CreateAnnotation(ctx, &Annotation{ProjectID: project1, FilePath: "p1b.go", StartLine: 2, Category: "xss", Severity: "high", Status: "valid"})
	s.CreateAnnotation(ctx, &Annotation{ProjectID: project2, FilePath: "p2.go", StartLine: 3, Category: "xss", Severity: "high", Status: "valid"})

	// List only project1 annotations
	annotations, err := s.ListAnnotationsByProject(ctx, project1)
	if err != nil {
		t.Fatalf("ListAnnotationsByProject() failed: %v", err)
	}
	if len(annotations) != 2 {
		t.Errorf("ListAnnotationsByProject(project1) returned %d annotations, want 2", len(annotations))
	}
	for _, a := range annotations {
		if a.ProjectID != project1 {
			t.Errorf("annotation has ProjectID = %d, want %d", a.ProjectID, project1)
		}
	}
}

func TestUpdateAnnotation(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	id, _ := s.CreateAnnotation(ctx, &Annotation{
		ProjectID: projectID,
		FilePath:  "old.go",
		StartLine: 10,
		Category:  "xss",
		Severity:  "low",
		Status:    "valid",
	})

	// Update the annotation
	updated := &Annotation{
		ID:        id,
		FilePath:  "new.go",
		StartLine: 20,
		EndLine:   sql.NullInt64{Int64: 25, Valid: true},
		CWEID:     sql.NullString{String: "CWE-79", Valid: true},
		Category:  "xss-reflected",
		Severity:  "high",
		Status:    "disputed",
	}
	err := s.UpdateAnnotation(ctx, updated)
	if err != nil {
		t.Fatalf("UpdateAnnotation() failed: %v", err)
	}

	got, err := s.GetAnnotation(ctx, id)
	if err != nil {
		t.Fatalf("GetAnnotation() failed: %v", err)
	}

	if got.FilePath != "new.go" {
		t.Errorf("FilePath = %q, want %q", got.FilePath, "new.go")
	}
	if got.StartLine != 20 {
		t.Errorf("StartLine = %d, want 20", got.StartLine)
	}
	if got.Severity != "high" {
		t.Errorf("Severity = %q, want %q", got.Severity, "high")
	}
	if got.Status != "disputed" {
		t.Errorf("Status = %q, want %q", got.Status, "disputed")
	}
}

func TestUpdateAnnotationNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	err := s.UpdateAnnotation(ctx, &Annotation{
		ID:        9999,
		FilePath:  "test.go",
		StartLine: 1,
		Category:  "xss",
		Severity:  "low",
		Status:    "valid",
	})
	if err != ErrNotFound {
		t.Errorf("UpdateAnnotation() error = %v, want ErrNotFound", err)
	}
}

func TestDeleteAnnotation(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	id, _ := s.CreateAnnotation(ctx, &Annotation{
		ProjectID: projectID,
		FilePath:  "test.go",
		StartLine: 1,
		Category:  "xss",
		Severity:  "low",
		Status:    "valid",
	})

	err := s.DeleteAnnotation(ctx, id)
	if err != nil {
		t.Fatalf("DeleteAnnotation() failed: %v", err)
	}

	_, err = s.GetAnnotation(ctx, id)
	if err != ErrNotFound {
		t.Errorf("GetAnnotation() after delete: error = %v, want ErrNotFound", err)
	}
}

func TestDeleteAnnotationNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	err := s.DeleteAnnotation(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("DeleteAnnotation() error = %v, want ErrNotFound", err)
	}
}

func TestDeleteAnnotationRemovesOnlyTarget(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	id1, _ := s.CreateAnnotation(ctx, &Annotation{ProjectID: projectID, FilePath: "a.go", StartLine: 1, Category: "xss", Severity: "low", Status: "valid"})
	id2, _ := s.CreateAnnotation(ctx, &Annotation{ProjectID: projectID, FilePath: "b.go", StartLine: 2, Category: "xss", Severity: "low", Status: "valid"})

	// Delete first
	s.DeleteAnnotation(ctx, id1)

	// Second should still exist
	_, err := s.GetAnnotation(ctx, id2)
	if err != nil {
		t.Errorf("GetAnnotation(id2) after deleting id1: error = %v, want nil", err)
	}
}

func TestBulkCreateAnnotations(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	annotations := []Annotation{
		{ProjectID: projectID, FilePath: "a.go", StartLine: 1, Category: "xss", Severity: "low", Status: "valid"},
		{ProjectID: projectID, FilePath: "b.go", StartLine: 2, Category: "sql-injection", Severity: "high", Status: "valid"},
		{ProjectID: projectID, FilePath: "c.go", StartLine: 3, Category: "path-traversal", Severity: "medium", Status: "valid"},
	}

	err := s.BulkCreateAnnotations(ctx, annotations)
	if err != nil {
		t.Fatalf("BulkCreateAnnotations() failed: %v", err)
	}

	// Verify all were inserted
	list, err := s.ListAnnotationsByProject(ctx, projectID)
	if err != nil {
		t.Fatalf("ListAnnotationsByProject() failed: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 annotations, got %d", len(list))
	}
}

func TestBulkCreateAnnotationsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	err := s.BulkCreateAnnotations(ctx, []Annotation{})
	if err != nil {
		t.Errorf("BulkCreateAnnotations(empty) failed: %v", err)
	}
}

func TestBulkCreateAnnotationsTransactional(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projectID := createTestProject(t, s)

	// Second annotation has invalid project_id which should fail FK constraint
	annotations := []Annotation{
		{ProjectID: projectID, FilePath: "good.go", StartLine: 1, Category: "xss", Severity: "low", Status: "valid"},
		{ProjectID: 99999, FilePath: "bad.go", StartLine: 2, Category: "xss", Severity: "low", Status: "valid"}, // Invalid project_id
	}

	err := s.BulkCreateAnnotations(ctx, annotations)
	if err == nil {
		t.Error("BulkCreateAnnotations() with invalid project_id should fail")
	}

	// Verify none were inserted (all-or-nothing)
	list, err := s.ListAnnotationsByProject(ctx, projectID)
	if err != nil {
		t.Fatalf("ListAnnotationsByProject() failed: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 annotations after failed bulk insert, got %d", len(list))
	}
}

func TestCreateAnnotationInvalidProjectFails(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.CreateAnnotation(ctx, &Annotation{
		ProjectID: 99999, // Non-existent
		FilePath:  "test.go",
		StartLine: 1,
		Category:  "xss",
		Severity:  "low",
		Status:    "valid",
	})
	if err == nil {
		t.Error("CreateAnnotation() with invalid project_id should fail")
	}
}
