package store

import (
	"context"
	"database/sql"
	"testing"
)

func setupTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() failed: %v", err)
	}
	return s
}

func TestCreateGetProjectRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	p := &CorpusProject{
		Name:      "test-project",
		SourceURL: sql.NullString{String: "https://github.com/example/test", Valid: true},
		LocalPath: "/tmp/test-project",
		Language:  sql.NullString{String: "go", Valid: true},
		CommitSHA: sql.NullString{String: "abc123", Valid: true},
	}

	id, err := s.CreateProject(ctx, p)
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	got, err := s.GetProject(ctx, id)
	if err != nil {
		t.Fatalf("GetProject() failed: %v", err)
	}
	if got.Name != p.Name {
		t.Errorf("Name = %q, want %q", got.Name, p.Name)
	}
	if got.SourceURL != p.SourceURL {
		t.Errorf("SourceURL = %v, want %v", got.SourceURL, p.SourceURL)
	}
	if got.LocalPath != p.LocalPath {
		t.Errorf("LocalPath = %q, want %q", got.LocalPath, p.LocalPath)
	}
	if got.Language != p.Language {
		t.Errorf("Language = %v, want %v", got.Language, p.Language)
	}
	if got.CommitSHA != p.CommitSHA {
		t.Errorf("CommitSHA = %v, want %v", got.CommitSHA, p.CommitSHA)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestGetProjectByName(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	p := &CorpusProject{
		Name:      "unique-name",
		LocalPath: "/tmp/unique",
	}

	id, err := s.CreateProject(ctx, p)
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	got, err := s.GetProjectByName(ctx, "unique-name")
	if err != nil {
		t.Fatalf("GetProjectByName() failed: %v", err)
	}
	if got.ID != id {
		t.Errorf("ID = %d, want %d", got.ID, id)
	}
	if got.Name != p.Name {
		t.Errorf("Name = %q, want %q", got.Name, p.Name)
	}
}

func TestGetProjectByNameNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.GetProjectByName(ctx, "non-existent")
	if err != ErrNotFound {
		t.Errorf("GetProjectByName() error = %v, want ErrNotFound", err)
	}
}

func TestListProjects(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Create multiple projects
	for _, name := range []string{"project-a", "project-b", "project-c"} {
		_, err := s.CreateProject(ctx, &CorpusProject{Name: name, LocalPath: "/tmp/" + name})
		if err != nil {
			t.Fatalf("CreateProject(%s) failed: %v", name, err)
		}
	}

	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects() failed: %v", err)
	}
	if len(projects) != 3 {
		t.Errorf("ListProjects() returned %d projects, want 3", len(projects))
	}

	// Verify sorted by name
	if projects[0].Name != "project-a" || projects[1].Name != "project-b" || projects[2].Name != "project-c" {
		t.Errorf("ListProjects() not sorted by name: %v", projects)
	}
}

func TestListProjectsEmptyReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	projects, err := s.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects() failed: %v", err)
	}
	if projects == nil {
		t.Error("ListProjects() returned nil, want empty slice")
	}
	if len(projects) != 0 {
		t.Errorf("ListProjects() returned %d projects, want 0", len(projects))
	}
}

func TestDeleteProject(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	id, err := s.CreateProject(ctx, &CorpusProject{Name: "to-delete", LocalPath: "/tmp/delete"})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	err = s.DeleteProject(ctx, id)
	if err != nil {
		t.Fatalf("DeleteProject() failed: %v", err)
	}

	_, err = s.GetProject(ctx, id)
	if err != ErrNotFound {
		t.Errorf("GetProject() after delete: error = %v, want ErrNotFound", err)
	}
}

func TestDeleteProjectNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	err := s.DeleteProject(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("DeleteProject() error = %v, want ErrNotFound", err)
	}
}

func TestGetProjectNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.GetProject(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("GetProject() error = %v, want ErrNotFound", err)
	}
}

func TestCreateProjectDuplicateNameFails(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	p := &CorpusProject{Name: "duplicate", LocalPath: "/tmp/dup"}

	_, err := s.CreateProject(ctx, p)
	if err != nil {
		t.Fatalf("first CreateProject() failed: %v", err)
	}

	_, err = s.CreateProject(ctx, p)
	if err == nil {
		t.Error("second CreateProject() with duplicate name should fail")
	}
}

func TestDeleteProjectCascadesToAnnotations(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Create project
	projectID, err := s.CreateProject(ctx, &CorpusProject{Name: "cascade-test", LocalPath: "/tmp/cascade"})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}

	// Create annotation
	annotationID, err := s.CreateAnnotation(ctx, &Annotation{
		ProjectID: projectID,
		FilePath:  "test.go",
		StartLine: 10,
		Category:  "sql-injection",
		Severity:  "high",
		Status:    "valid",
	})
	if err != nil {
		t.Fatalf("CreateAnnotation() failed: %v", err)
	}

	// Verify annotation exists
	_, err = s.GetAnnotation(ctx, annotationID)
	if err != nil {
		t.Fatalf("GetAnnotation() before delete failed: %v", err)
	}

	// Delete project
	err = s.DeleteProject(ctx, projectID)
	if err != nil {
		t.Fatalf("DeleteProject() failed: %v", err)
	}

	// Verify annotation is cascade deleted
	_, err = s.GetAnnotation(ctx, annotationID)
	if err != ErrNotFound {
		t.Errorf("GetAnnotation() after cascade delete: error = %v, want ErrNotFound", err)
	}
}
