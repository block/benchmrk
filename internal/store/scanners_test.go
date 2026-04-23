package store

import (
	"context"
	"database/sql"
	"testing"
)

func TestCreateGetScannerRoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	sc := &Scanner{
		Name:        "semgrep",
		Version:     "1.50.0",
		DockerImage: "benchmrk/scanner-semgrep:1.50.0",
		ConfigJSON:  sql.NullString{String: `{"rules": ["auto"]}`, Valid: true},
	}

	id, err := s.CreateScanner(ctx, sc)
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive ID, got %d", id)
	}

	got, err := s.GetScanner(ctx, id)
	if err != nil {
		t.Fatalf("GetScanner() failed: %v", err)
	}
	if got.Name != sc.Name {
		t.Errorf("Name = %q, want %q", got.Name, sc.Name)
	}
	if got.Version != sc.Version {
		t.Errorf("Version = %q, want %q", got.Version, sc.Version)
	}
	if got.DockerImage != sc.DockerImage {
		t.Errorf("DockerImage = %q, want %q", got.DockerImage, sc.DockerImage)
	}
	if got.ConfigJSON != sc.ConfigJSON {
		t.Errorf("ConfigJSON = %v, want %v", got.ConfigJSON, sc.ConfigJSON)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestGetScannerByNameVersion(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	sc := &Scanner{
		Name:        "codeql",
		Version:     "2.15.0",
		DockerImage: "benchmrk/scanner-codeql:2.15.0",
	}

	id, err := s.CreateScanner(ctx, sc)
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}

	got, err := s.GetScannerByNameVersion(ctx, "codeql", "2.15.0")
	if err != nil {
		t.Fatalf("GetScannerByNameVersion() failed: %v", err)
	}
	if got.ID != id {
		t.Errorf("ID = %d, want %d", got.ID, id)
	}
	if got.Name != sc.Name {
		t.Errorf("Name = %q, want %q", got.Name, sc.Name)
	}
	if got.Version != sc.Version {
		t.Errorf("Version = %q, want %q", got.Version, sc.Version)
	}
}

func TestGetScannerByNameVersionNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.GetScannerByNameVersion(ctx, "nonexistent", "0.0.0")
	if err != ErrNotFound {
		t.Errorf("GetScannerByNameVersion() error = %v, want ErrNotFound", err)
	}
}

func TestCreateScannerDuplicateNameVersionFails(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	sc := &Scanner{
		Name:        "semgrep",
		Version:     "1.50.0",
		DockerImage: "benchmrk/scanner-semgrep:1.50.0",
	}

	_, err := s.CreateScanner(ctx, sc)
	if err != nil {
		t.Fatalf("first CreateScanner() failed: %v", err)
	}

	_, err = s.CreateScanner(ctx, sc)
	if err == nil {
		t.Error("second CreateScanner() with duplicate name+version should fail")
	}
}

func TestListScanners(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()

	// Create multiple scanners
	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, err := s.CreateScanner(ctx, &Scanner{
			Name:        name,
			Version:     "1.0.0",
			DockerImage: "benchmrk/scanner-" + name + ":1.0.0",
		})
		if err != nil {
			t.Fatalf("CreateScanner(%s) failed: %v", name, err)
		}
	}

	scanners, err := s.ListScanners(ctx)
	if err != nil {
		t.Fatalf("ListScanners() failed: %v", err)
	}
	if len(scanners) != 3 {
		t.Errorf("ListScanners() returned %d scanners, want 3", len(scanners))
	}

	// Verify sorted by name
	if scanners[0].Name != "alpha" || scanners[1].Name != "beta" || scanners[2].Name != "gamma" {
		t.Errorf("ListScanners() not sorted by name: %v", scanners)
	}
}

func TestListScannersEmptyReturnsEmptySlice(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	scanners, err := s.ListScanners(ctx)
	if err != nil {
		t.Fatalf("ListScanners() failed: %v", err)
	}
	if scanners == nil {
		t.Error("ListScanners() returned nil, want empty slice")
	}
	if len(scanners) != 0 {
		t.Errorf("ListScanners() returned %d scanners, want 0", len(scanners))
	}
}

func TestDeleteScanner(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	id, err := s.CreateScanner(ctx, &Scanner{
		Name:        "to-delete",
		Version:     "1.0.0",
		DockerImage: "benchmrk/scanner-delete:1.0.0",
	})
	if err != nil {
		t.Fatalf("CreateScanner() failed: %v", err)
	}

	err = s.DeleteScanner(ctx, id)
	if err != nil {
		t.Fatalf("DeleteScanner() failed: %v", err)
	}

	_, err = s.GetScanner(ctx, id)
	if err != ErrNotFound {
		t.Errorf("GetScanner() after delete: error = %v, want ErrNotFound", err)
	}
}

func TestDeleteScannerNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	err := s.DeleteScanner(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("DeleteScanner() error = %v, want ErrNotFound", err)
	}
}

func TestGetScannerNotFound(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()

	ctx := context.Background()
	_, err := s.GetScanner(ctx, 9999)
	if err != ErrNotFound {
		t.Errorf("GetScanner() error = %v, want ErrNotFound", err)
	}
}
