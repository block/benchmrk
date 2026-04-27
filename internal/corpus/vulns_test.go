package corpus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeVulnFile serialises a minimal vulnerability JSON to a temp file
// and returns its path. Each name gets one evidence row at a distinct
// line so the file validates.
func writeVulnFile(t *testing.T, names ...string) string {
	t.Helper()
	var entries []string
	for i, n := range names {
		entries = append(entries, `{
			"name": "`+n+`",
			"evidence": [{"file":"app.go","line":`+lineN(i+1)+`,"category":"test","severity":"high"}]
		}`)
	}
	body := `{"vulnerabilities":[` + strings.Join(entries, ",") + `]}`
	path := filepath.Join(t.TempDir(), "vulns.json")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write vuln file: %v", err)
	}
	return path
}

func lineN(n int) string {
	// Cheap int→string without importing strconv for a test helper.
	// n is small (test fixtures), so this is fine.
	return string(rune('0' + n))
}

func setupProjectForImport(t *testing.T) (*Service, string) {
	t.Helper()
	s := setupTestStore(t)
	svc := New(s)
	dir := createTestDir(t, map[string]string{"app.go": "package main"})
	if _, err := svc.AddProject(context.Background(), "p", dir, "go", ""); err != nil {
		t.Fatalf("AddProject: %v", err)
	}
	return svc, "p"
}

// The scenario that burned us in production: same file imported twice
// without --replace. First import: 2 vulns land. Second import of the
// same 2 names must refuse — not silently double the ground truth.
func TestImportVulns_RefusesDuplicateImportWithoutReplace(t *testing.T) {
	svc, project := setupProjectForImport(t)
	ctx := context.Background()

	file := writeVulnFile(t, "sqli-login", "xss-search")

	// First import: succeeds.
	n, err := svc.ImportAnnotations(ctx, project, file)
	if err != nil {
		t.Fatalf("first import failed: %v", err)
	}
	if n != 2 {
		t.Fatalf("first import: got %d evidence rows, want 2", n)
	}

	// Second import, no --replace: must refuse with a useful error.
	_, err = svc.ImportAnnotations(ctx, project, file)
	if err == nil {
		t.Fatal("second import without --replace succeeded — would have doubled the ground truth")
	}

	msg := err.Error()
	if !strings.Contains(msg, "2 vulnerability name(s) already exist") {
		t.Errorf("error should state the collision count, got: %v", err)
	}
	if !strings.Contains(msg, "sqli-login") || !strings.Contains(msg, "xss-search") {
		t.Errorf("error should name the colliding vulns, got: %v", err)
	}
	if !strings.Contains(msg, "--replace") {
		t.Errorf("error should suggest --replace, got: %v", err)
	}
	if !strings.Contains(msg, "halve recall") {
		t.Errorf("error should explain WHY this matters (halved recall), got: %v", err)
	}
}

// Same scenario, but WITH --replace: must succeed and leave exactly 2
// vulns, not 4.
func TestImportVulns_ReplaceAllowsReimport(t *testing.T) {
	svc, project := setupProjectForImport(t)
	ctx := context.Background()

	file := writeVulnFile(t, "sqli-login", "xss-search")
	svc.ImportAnnotations(ctx, project, file)

	// Reimport with --replace.
	_, err := svc.ImportAnnotations(ctx, project, file, true)
	if err != nil {
		t.Fatalf("reimport with --replace failed: %v", err)
	}

	// Still 2 vulns, not 4.
	proj, _ := svc.store.GetProjectByName(ctx, project)
	vulns, _ := svc.store.ListVulnerabilitiesByProject(ctx, proj.ID)
	if len(vulns) != 2 {
		t.Errorf("after --replace reimport: got %d vulns, want 2 (not doubled)", len(vulns))
	}
}

// Partial overlap: file has {A, B, C}, DB has {B}. Only B collides.
// Must still refuse — one phantom FN is one too many — but the error
// should say "1 name", not "3 names".
func TestImportVulns_PartialOverlapStillRefuses(t *testing.T) {
	svc, project := setupProjectForImport(t)
	ctx := context.Background()

	// Seed with just B.
	svc.ImportAnnotations(ctx, project, writeVulnFile(t, "vuln-b"))

	// Import A, B, C — B collides.
	_, err := svc.ImportAnnotations(ctx, project, writeVulnFile(t, "vuln-a", "vuln-b", "vuln-c"))
	if err == nil {
		t.Fatal("partial overlap should refuse — one phantom FN is still wrong")
	}
	if !strings.Contains(err.Error(), "1 vulnerability name(s)") {
		t.Errorf("should report exactly 1 collision, got: %v", err)
	}
	if !strings.Contains(err.Error(), "vuln-b") {
		t.Errorf("should name the one colliding vuln, got: %v", err)
	}
	if strings.Contains(err.Error(), "vuln-a") || strings.Contains(err.Error(), "vuln-c") {
		t.Errorf("should NOT name non-colliding vulns, got: %v", err)
	}
}

// Legitimate append: DB has {A}, file has {B, C} — no overlap. Must
// succeed and leave {A, B, C}. The guardrail blocks collisions, not
// additions.
func TestImportVulns_DisjointAppendSucceeds(t *testing.T) {
	svc, project := setupProjectForImport(t)
	ctx := context.Background()

	svc.ImportAnnotations(ctx, project, writeVulnFile(t, "existing"))

	_, err := svc.ImportAnnotations(ctx, project, writeVulnFile(t, "new-one", "new-two"))
	if err != nil {
		t.Fatalf("disjoint append should succeed, got: %v", err)
	}

	proj, _ := svc.store.GetProjectByName(ctx, project)
	vulns, _ := svc.store.ListVulnerabilitiesByProject(ctx, proj.ID)
	if len(vulns) != 3 {
		t.Errorf("got %d vulns, want 3 (1 existing + 2 appended)", len(vulns))
	}
}

// In-file duplicate: same name twice in one JSON. Different failure
// mode, same halving symptom. Should fail BEFORE hitting the DB so the
// error is about the file, not the project state.
func TestImportVulns_RefusesInFileDuplicate(t *testing.T) {
	svc, project := setupProjectForImport(t)

	file := writeVulnFile(t, "dup-name", "other", "dup-name")
	_, err := svc.ImportAnnotations(context.Background(), project, file)
	if err == nil {
		t.Fatal("in-file duplicate should be refused")
	}

	msg := err.Error()
	if !strings.Contains(msg, `"dup-name" appears twice`) {
		t.Errorf("should name the duplicate, got: %v", err)
	}
	if !strings.Contains(msg, "positions 1 and 3") {
		t.Errorf("should cite both positions for easy find-in-file, got: %v", err)
	}
	if !strings.Contains(msg, "evidence[]") {
		t.Errorf("should suggest the multi-evidence fix, got: %v", err)
	}
}

// When the collision list is long, the error shows a sample plus
// "(+N more)" rather than a wall of names.
func TestImportVulns_TruncatesLongCollisionList(t *testing.T) {
	svc, project := setupProjectForImport(t)
	ctx := context.Background()

	names := []string{"v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"}
	svc.ImportAnnotations(ctx, project, writeVulnFile(t, names...))

	_, err := svc.ImportAnnotations(ctx, project, writeVulnFile(t, names...))
	if err == nil {
		t.Fatal("expected collision error")
	}
	if !strings.Contains(err.Error(), "8 vulnerability name(s)") {
		t.Errorf("should report full count, got: %v", err)
	}
	if !strings.Contains(err.Error(), "(+3 more)") {
		t.Errorf("should truncate to 5 + '(+3 more)', got: %v", err)
	}
}
