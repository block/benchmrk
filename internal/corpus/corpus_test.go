package corpus

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

func setupTestStore(t *testing.T) *store.Store {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	s, err := store.New(dbPath)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	if err := s.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	t.Cleanup(func() { s.Close() })
	return s
}

func createTestDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("create dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}
	return dir
}

func TestAddProject_LocalPath_CreatesRecord(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{
		"main.go": "package main",
	})

	ctx := context.Background()
	project, err := svc.AddProject(ctx, "test-project", testDir, "", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	if project.Name != "test-project" {
		t.Errorf("expected name 'test-project', got %q", project.Name)
	}
	if project.LocalPath != testDir {
		t.Errorf("expected local path %q, got %q", testDir, project.LocalPath)
	}
	if project.ID == 0 {
		t.Error("expected non-zero ID")
	}
}

func TestAddProject_NonExistentPath_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	ctx := context.Background()
	_, err := svc.AddProject(ctx, "test-project", "/nonexistent/path/that/does/not/exist", "", "")
	if err != ErrPathNotFound {
		t.Errorf("expected ErrPathNotFound, got %v", err)
	}
}

func TestAddProject_DuplicateName_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{
		"main.go": "package main",
	})

	ctx := context.Background()
	_, err := svc.AddProject(ctx, "duplicate", testDir, "", "")
	if err != nil {
		t.Fatalf("first AddProject: %v", err)
	}

	// Create a second test directory for the duplicate attempt
	testDir2 := createTestDir(t, map[string]string{
		"app.py": "print('hello')",
	})

	_, err = svc.AddProject(ctx, "duplicate", testDir2, "", "")
	if err != ErrDuplicateName {
		t.Errorf("expected ErrDuplicateName, got %v", err)
	}
}

func TestAddProject_EmptyName_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{
		"main.go": "package main",
	})

	ctx := context.Background()
	_, err := svc.AddProject(ctx, "", testDir, "", "")
	if err != ErrEmptyName {
		t.Errorf("expected ErrEmptyName, got %v", err)
	}
}

func TestListProjects_ReturnsAllProjects(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir1 := createTestDir(t, map[string]string{"main.go": "package main"})
	testDir2 := createTestDir(t, map[string]string{"app.py": "print('hi')"})

	ctx := context.Background()
	_, err := svc.AddProject(ctx, "project-a", testDir1, "go", "")
	if err != nil {
		t.Fatalf("AddProject 1: %v", err)
	}
	_, err = svc.AddProject(ctx, "project-b", testDir2, "python", "")
	if err != nil {
		t.Fatalf("AddProject 2: %v", err)
	}

	projects, err := svc.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}

	if len(projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(projects))
	}

	// Verify sorted by name (project-a before project-b)
	if len(projects) >= 2 {
		if projects[0].Name != "project-a" {
			t.Errorf("expected first project 'project-a', got %q", projects[0].Name)
		}
		if projects[1].Name != "project-b" {
			t.Errorf("expected second project 'project-b', got %q", projects[1].Name)
		}
	}
}

func TestListProjects_NoProjects_ReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	ctx := context.Background()
	projects, err := svc.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}

	if projects == nil {
		t.Error("expected non-nil slice, got nil")
	}
	if len(projects) != 0 {
		t.Errorf("expected 0 projects, got %d", len(projects))
	}
}

func TestShowProject_ReturnsProjectDetails(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})

	ctx := context.Background()
	_, err := svc.AddProject(ctx, "show-test", testDir, "go", "abc123")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	project, err := svc.ShowProject(ctx, "show-test")
	if err != nil {
		t.Fatalf("ShowProject: %v", err)
	}

	if project.Name != "show-test" {
		t.Errorf("expected name 'show-test', got %q", project.Name)
	}
	if !project.Language.Valid || project.Language.String != "go" {
		t.Errorf("expected language 'go', got %v", project.Language)
	}
	if !project.CommitSHA.Valid || project.CommitSHA.String != "abc123" {
		t.Errorf("expected commit 'abc123', got %v", project.CommitSHA)
	}
}

func TestShowProject_NotFound_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	ctx := context.Background()
	_, err := svc.ShowProject(ctx, "nonexistent")
	if err != ErrProjectNotFound {
		t.Errorf("expected ErrProjectNotFound, got %v", err)
	}
}

func TestRemoveProject_DeletesFromStore(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	testDir := createTestDir(t, map[string]string{"main.go": "package main"})

	ctx := context.Background()
	_, err := svc.AddProject(ctx, "to-remove", testDir, "", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	// Verify it exists
	_, err = svc.ShowProject(ctx, "to-remove")
	if err != nil {
		t.Fatalf("ShowProject before remove: %v", err)
	}

	// Remove it
	err = svc.RemoveProject(ctx, "to-remove")
	if err != nil {
		t.Fatalf("RemoveProject: %v", err)
	}

	// Verify it's gone
	_, err = svc.ShowProject(ctx, "to-remove")
	if err != ErrProjectNotFound {
		t.Errorf("expected ErrProjectNotFound after removal, got %v", err)
	}
}

func TestRemoveProject_NotFound_ReturnsError(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	ctx := context.Background()
	err := svc.RemoveProject(ctx, "nonexistent")
	if err != ErrProjectNotFound {
		t.Errorf("expected ErrProjectNotFound, got %v", err)
	}
}

func TestLanguageDetection_PicksMostCommonExtension(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	// Create a directory with mostly Go files
	testDir := createTestDir(t, map[string]string{
		"main.go":     "package main",
		"handler.go":  "package main",
		"util.go":     "package main",
		"config.json": "{}",
		"README.md":   "# readme",
		"script.py":   "print('hi')",
		"Makefile":    "build:",
	})

	ctx := context.Background()
	project, err := svc.AddProject(ctx, "lang-test", testDir, "", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	if !project.Language.Valid || project.Language.String != "go" {
		t.Errorf("expected detected language 'go', got %v", project.Language)
	}
}

func TestLanguageDetection_ExplicitOverridesDetection(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	// Create a directory with mostly Go files
	testDir := createTestDir(t, map[string]string{
		"main.go":    "package main",
		"handler.go": "package main",
	})

	ctx := context.Background()
	// Explicitly set language to python
	project, err := svc.AddProject(ctx, "explicit-lang", testDir, "python", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	if !project.Language.Valid || project.Language.String != "python" {
		t.Errorf("expected language 'python', got %v", project.Language)
	}
}

func TestLanguageDetection_EmptyDirectory_NoLanguage(t *testing.T) {
	s := setupTestStore(t)
	svc := New(s)

	// Create an empty directory
	testDir := t.TempDir()

	ctx := context.Background()
	project, err := svc.AddProject(ctx, "empty-dir", testDir, "", "")
	if err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	if project.Language.Valid {
		t.Errorf("expected no language for empty directory, got %q", project.Language.String)
	}
}
