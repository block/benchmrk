package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

// Post migration 010, annotation-group write methods are hard-deprecated
// (they return errGroupsMigrated) and read methods synthesize groups
// from multi-evidence vulnerabilities. These tests cover both sides.

var groupsTestCounter int

func createTestProjectForGroups(t *testing.T, s *Store) int64 {
	t.Helper()
	groupsTestCounter++
	ctx := context.Background()
	id, err := s.CreateProject(ctx, &CorpusProject{
		Name:      "test-project-groups-" + string(rune('a'+groupsTestCounter)),
		LocalPath: "/tmp/test-groups",
	})
	if err != nil {
		t.Fatalf("CreateProject() failed: %v", err)
	}
	return id
}

// createMultiEvidenceVuln is the setup helper for the read-path tests.
// A multi-evidence vuln IS a group in compat terms.
func createMultiEvidenceVuln(t *testing.T, s *Store, projectID int64, name string, locations ...string) (vulnID int64, evidenceIDs []int64) {
	t.Helper()
	ctx := context.Background()
	vid, err := s.CreateVulnerability(ctx, &Vulnerability{
		ProjectID: projectID, Name: name, Criticality: "should", Status: "valid",
	})
	if err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}
	for _, loc := range locations {
		eid, err := s.CreateEvidence(ctx, &Evidence{
			VulnID: vid, FilePath: loc, StartLine: 10,
			Role: "sink", Category: "test", Severity: "high",
		})
		if err != nil {
			t.Fatalf("CreateEvidence: %v", err)
		}
		evidenceIDs = append(evidenceIDs, eid)
	}
	return vid, evidenceIDs
}

// ── Write methods: all error ────────────────────────────────────────

func TestGroupWritesRejectedPostMigration(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()

	if _, err := s.CreateAnnotationGroup(ctx, &AnnotationGroup{}); !errors.Is(err, errGroupsMigrated) {
		t.Errorf("CreateAnnotationGroup: got %v, want errGroupsMigrated", err)
	}
	if err := s.AddAnnotationToGroup(ctx, 1, 1, "sink"); !errors.Is(err, errGroupsMigrated) {
		t.Errorf("AddAnnotationToGroup: got %v, want errGroupsMigrated", err)
	}
	if err := s.RemoveAnnotationFromGroup(ctx, 1, 1); !errors.Is(err, errGroupsMigrated) {
		t.Errorf("RemoveAnnotationFromGroup: got %v, want errGroupsMigrated", err)
	}
	if err := s.DeleteAnnotationGroup(ctx, 1); !errors.Is(err, errGroupsMigrated) {
		t.Errorf("DeleteAnnotationGroup: got %v, want errGroupsMigrated", err)
	}
}

// ── Read methods: synthesize from multi-evidence vulns ──────────────

func TestListAnnotationGroupsByProject_Synthesized(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	// One multi-evidence vuln (is a group) and one solo (is not).
	multiVID, _ := createMultiEvidenceVuln(t, s, pid, "multi", "a.go", "b.go")
	createMultiEvidenceVuln(t, s, pid, "solo", "c.go")

	groups, err := s.ListAnnotationGroupsByProject(ctx, pid)
	if err != nil {
		t.Fatalf("ListAnnotationGroupsByProject: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1 (only multi-evidence vulns are groups)", len(groups))
	}
	if groups[0].ID != multiVID {
		t.Errorf("group ID = %d, want %d (the vuln ID)", groups[0].ID, multiVID)
	}
	if !groups[0].Name.Valid || groups[0].Name.String != "multi" {
		t.Errorf("group name = %v, want 'multi' (the vuln name)", groups[0].Name)
	}
}

func TestGetAnnotationGroup_Synthesized(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	multiVID, _ := createMultiEvidenceVuln(t, s, pid, "multi", "a.go", "b.go")
	soloVID, _ := createMultiEvidenceVuln(t, s, pid, "solo", "c.go")

	g, err := s.GetAnnotationGroup(ctx, multiVID)
	if err != nil {
		t.Fatalf("GetAnnotationGroup(multi): %v", err)
	}
	if g.ID != multiVID {
		t.Errorf("ID = %d, want %d", g.ID, multiVID)
	}

	// Solo vuln is not a group.
	if _, err := s.GetAnnotationGroup(ctx, soloVID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAnnotationGroup(solo): got %v, want ErrNotFound", err)
	}
}

func TestListGroupMembers_Synthesized(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	vid, eids := createMultiEvidenceVuln(t, s, pid, "g", "a.go", "b.go", "c.go")

	members, err := s.ListGroupMembers(ctx, vid)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("got %d members, want 3", len(members))
	}
	for i, m := range members {
		if m.GroupID != vid {
			t.Errorf("member %d GroupID = %d, want %d (vuln ID)", i, m.GroupID, vid)
		}
		if m.AnnotationID != eids[i] {
			t.Errorf("member %d AnnotationID = %d, want %d (evidence ID)", i, m.AnnotationID, eids[i])
		}
	}
}

func TestListGroupsByAnnotation_Synthesized(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	vid, eids := createMultiEvidenceVuln(t, s, pid, "g", "a.go", "b.go")
	_, soloEids := createMultiEvidenceVuln(t, s, pid, "solo", "c.go")

	// Evidence in a multi-evidence vuln belongs to one "group" (its vuln).
	groups, err := s.ListGroupsByAnnotation(ctx, eids[0])
	if err != nil {
		t.Fatalf("ListGroupsByAnnotation(multi): %v", err)
	}
	if len(groups) != 1 || groups[0].ID != vid {
		t.Errorf("got %v, want one group with ID %d", groups, vid)
	}

	// Solo evidence belongs to no group.
	groups, err = s.ListGroupsByAnnotation(ctx, soloEids[0])
	if err != nil {
		t.Fatalf("ListGroupsByAnnotation(solo): %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("solo evidence in %d groups, want 0", len(groups))
	}
}

func TestListAllGroupMembersByProject_Synthesized(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	createMultiEvidenceVuln(t, s, pid, "g1", "a.go", "b.go")         // 2 members
	createMultiEvidenceVuln(t, s, pid, "g2", "c.go", "d.go", "e.go") // 3 members
	createMultiEvidenceVuln(t, s, pid, "solo", "f.go")               // not a group

	members, err := s.ListAllGroupMembersByProject(ctx, pid)
	if err != nil {
		t.Fatalf("ListAllGroupMembersByProject: %v", err)
	}
	if len(members) != 5 {
		t.Errorf("got %d members, want 5 (2+3, solo excluded)", len(members))
	}

	// This is what annotationHash consumes — verify it's deterministically
	// ordered so the hash is stable.
	for i := 1; i < len(members); i++ {
		prev, curr := members[i-1], members[i]
		if prev.GroupID > curr.GroupID ||
			(prev.GroupID == curr.GroupID && prev.AnnotationID > curr.AnnotationID) {
			t.Errorf("members not sorted: [%d]={%d,%d} after [%d]={%d,%d}",
				i, curr.GroupID, curr.AnnotationID, i-1, prev.GroupID, prev.AnnotationID)
		}
	}
}

// ── Compat shim: annotation reads still work ────────────────────────

func TestAnnotationCompat_ReadThroughMultiEvidenceVuln(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	// Create a vuln with two evidence rows and two acceptable CWEs.
	vid, eids := createMultiEvidenceVuln(t, s, pid, "task-idor", "api.js", "tasks.js")
	s.AddVulnCWE(ctx, vid, "CWE-639")
	s.AddVulnCWE(ctx, vid, "CWE-862")

	// GetAnnotation on an evidence ID should return a synthesized
	// Annotation with the vuln's status and ONE of its CWEs (first
	// alphabetically — the compat select uses ORDER BY cwe_id LIMIT 1).
	a, err := s.GetAnnotation(ctx, eids[0])
	if err != nil {
		t.Fatalf("GetAnnotation: %v", err)
	}
	if a.ID != eids[0] {
		t.Errorf("ID = %d, want %d (evidence ID preserved)", a.ID, eids[0])
	}
	if a.Status != "valid" {
		t.Errorf("Status = %q, want 'valid' (from vuln)", a.Status)
	}
	if !a.CWEID.Valid || a.CWEID.String != "CWE-639" {
		t.Errorf("CWEID = %v, want 'CWE-639' (first of {639,862} alphabetically)", a.CWEID)
	}

	// ListAnnotationsByProject should return one row per evidence.
	anns, err := s.ListAnnotationsByProject(ctx, pid)
	if err != nil {
		t.Fatalf("ListAnnotationsByProject: %v", err)
	}
	if len(anns) != 2 {
		t.Errorf("got %d annotations, want 2 (one per evidence row)", len(anns))
	}
}

func TestAnnotationCompat_DeleteLastEvidenceDeletesVuln(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	vid, eids := createMultiEvidenceVuln(t, s, pid, "v", "a.go", "b.go")

	// Delete one evidence row; vuln survives.
	if err := s.DeleteAnnotation(ctx, eids[0]); err != nil {
		t.Fatalf("DeleteAnnotation(first): %v", err)
	}
	if _, err := s.GetVulnerability(ctx, vid); err != nil {
		t.Errorf("vuln gone after deleting one of two evidence rows: %v", err)
	}

	// Delete the other; vuln goes with it.
	if err := s.DeleteAnnotation(ctx, eids[1]); err != nil {
		t.Fatalf("DeleteAnnotation(last): %v", err)
	}
	if _, err := s.GetVulnerability(ctx, vid); !errors.Is(err, ErrNotFound) {
		t.Errorf("vuln survived deletion of last evidence: %v", err)
	}
}

// Regression guard: the compat CreateAnnotation → GetAnnotation round
// trip should be lossless for every field the old API exposed.
func TestAnnotationCompat_RoundTrip(t *testing.T) {
	s := setupTestStore(t)
	defer s.Close()
	ctx := context.Background()
	pid := createTestProjectForGroups(t, s)

	in := &Annotation{
		ProjectID:   pid,
		FilePath:    "routes/auth.js",
		StartLine:   42,
		EndLine:     sql.NullInt64{Int64: 50, Valid: true},
		CWEID:       sql.NullString{String: "CWE-89", Valid: true},
		Category:    "sql-injection",
		Severity:    "critical",
		Description: sql.NullString{String: "test desc", Valid: true},
		Status:      "valid",
		AnnotatedBy: sql.NullString{String: "alice", Valid: true},
	}
	id, err := s.CreateAnnotation(ctx, in)
	if err != nil {
		t.Fatalf("CreateAnnotation: %v", err)
	}

	out, err := s.GetAnnotation(ctx, id)
	if err != nil {
		t.Fatalf("GetAnnotation: %v", err)
	}

	check := func(field string, got, want any) {
		if got != want {
			t.Errorf("%s: got %v, want %v", field, got, want)
		}
	}
	check("ID", out.ID, id)
	check("ProjectID", out.ProjectID, in.ProjectID)
	check("FilePath", out.FilePath, in.FilePath)
	check("StartLine", out.StartLine, in.StartLine)
	check("EndLine", out.EndLine, in.EndLine)
	check("CWEID", out.CWEID, in.CWEID)
	check("Category", out.Category, in.Category)
	check("Severity", out.Severity, in.Severity)
	check("Description", out.Description, in.Description)
	check("Status", out.Status, in.Status)
	check("AnnotatedBy", out.AnnotatedBy, in.AnnotatedBy)
}
