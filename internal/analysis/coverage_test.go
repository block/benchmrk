package analysis

import (
	"context"
	"database/sql"
	"math"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

// coverageFixture builds a ground-truth universe and a per-scanner catch
// map, then wires the mock so ListSatisfiedVulns returns the right
// subset per scanner. The mock treats one annotation as one vuln
// (annotationToVuln), so vulnIDs here double as annotation IDs.
//
// Every scanner gets exactly one run — multi-iteration flakiness is
// tested separately with a dedicated setup.
func coverageFixture(t *testing.T, ms *mockStore, vulns map[int64]struct {
	tier   string
	status store.AnnotationStatus
}, scanners map[int64]struct {
	name   string
	caught []int64
}) {
	t.Helper()
	const projectID = 1
	ms.projects[projectID] = &store.CorpusProject{ID: projectID, Name: "p"}

	for vid, v := range vulns {
		// Mock derives vuln Criticality from annotationToVuln, which
		// hardcodes "should". Override by storing vuln directly? No —
		// easier: use a tier-aware variant of annotationToVuln. But
		// the mock uses a fixed conversion. Instead: the mock's
		// ListVulnerabilitiesByProject and ListSatisfiedVulns both go
		// through annotationToVuln, so we need the annotation to carry
		// tier info somewhere it survives the round trip.
		//
		// Simplest path: annotationToVuln maps Category → Name and
		// hardcodes Criticality="should". That means tests can't
		// exercise tier-sorting through the mock. Acceptable for now —
		// tier sorting is exercised directly in TestTierSort, and the
		// set-overlap logic doesn't care about tier.
		_ = v.tier // documented limitation; see TestTierSort
		ms.annotations[vid] = &store.Annotation{
			ID: vid, ProjectID: projectID, Status: v.status,
			Category: "vuln-" + string(rune('a'+vid)),
		}
	}

	for sid, sc := range scanners {
		ms.scanners[sid] = &store.Scanner{ID: sid, Name: sc.name, Version: "1"}
		runID := sid * 100 // distinct per scanner, one run each
		ms.runs[runID] = &store.Run{ID: runID, ScannerID: sid, ProjectID: projectID, Status: store.RunStatusCompleted}
		if ms.runsByScannerProject[sid] == nil {
			ms.runsByScannerProject[sid] = map[int64][]store.Run{}
		}
		ms.runsByScannerProject[sid][projectID] = []store.Run{*ms.runs[runID]}

		// Matches: one synthetic finding per caught vuln. The mock's
		// ListSatisfiedVulns walks findingMatches[runID] and returns
		// annotations whose IDs appear there, so we just need the
		// AnnotationID to line up with a vuln ID.
		for _, vid := range sc.caught {
			ms.findingMatches[runID] = append(ms.findingMatches[runID], store.FindingMatch{
				FindingID: runID*10 + vid, AnnotationID: vid,
			})
		}
		ms.unmatchedFindings[runID] = []store.Finding{} // no FP noise by default
	}
}

// Vuln map: 1,2,3,4 valid + 5 invalid.
// A catches {1,2}, B catches {2,3}.
//
//	vuln 1 → only A → A's marginal
//	vuln 2 → both   → floor
//	vuln 3 → only B → B's marginal
//	vuln 4 → nobody → blind spot
//	vuln 5 → invalid, doesn't count toward anything
//
// Union catches {1,2,3} of 4 valid → 0.75. Best single catches 2/4 → 0.5.
// The 0.25 gap is the case for running both.
func TestCoverage_TwoScannerVenn(t *testing.T) {
	ms := newMockStore()
	coverageFixture(t, ms,
		map[int64]struct {
			tier   string
			status store.AnnotationStatus
		}{
			1: {"must", store.AnnotationStatusValid},
			2: {"should", store.AnnotationStatusValid},
			3: {"should", store.AnnotationStatusValid},
			4: {"may", store.AnnotationStatusValid},
			5: {"should", store.AnnotationStatusInvalid}, // decoy — must be excluded everywhere
		},
		map[int64]struct {
			name   string
			caught []int64
		}{
			10: {"scanner-a", []int64{1, 2}},
			20: {"scanner-b", []int64{2, 3}},
		},
	)

	cov, err := NewService(ms, nil).ComputeCoverage(context.Background(), []int64{10, 20}, 1)
	if err != nil {
		t.Fatalf("ComputeCoverage: %v", err)
	}

	if len(cov.CaughtByAll) != 1 || cov.CaughtByAll[0].ID != 2 {
		t.Errorf("CaughtByAll = %v, want [vuln 2]", vulnIDs(cov.CaughtByAll))
	}
	if len(cov.CaughtByNone) != 1 || cov.CaughtByNone[0].ID != 4 {
		t.Errorf("CaughtByNone = %v, want [vuln 4]", vulnIDs(cov.CaughtByNone))
	}
	// vuln 5 must appear NOWHERE — it's invalid.
	for _, v := range cov.CaughtByAll {
		if v.ID == 5 {
			t.Error("invalid vuln 5 leaked into CaughtByAll")
		}
	}
	for _, v := range cov.CaughtByNone {
		if v.ID == 5 {
			t.Error("invalid vuln 5 leaked into CaughtByNone — decoys are not blind spots")
		}
	}

	// Marginal: A uniquely catches 1, B uniquely catches 3.
	// Marginal slice is in scannerIDs order, so [0]=A [1]=B.
	if len(cov.Marginal[0].Unique) != 1 || cov.Marginal[0].Unique[0].ID != 1 {
		t.Errorf("scanner-a marginal = %v, want [vuln 1]", vulnIDs(cov.Marginal[0].Unique))
	}
	if len(cov.Marginal[1].Unique) != 1 || cov.Marginal[1].Unique[0].ID != 3 {
		t.Errorf("scanner-b marginal = %v, want [vuln 3]", vulnIDs(cov.Marginal[1].Unique))
	}

	if math.Abs(cov.UnionRecall-0.75) > 1e-9 {
		t.Errorf("UnionRecall = %v, want 0.75 (3 of 4 valid caught by someone)", cov.UnionRecall)
	}
	if math.Abs(cov.BestSingleRecall-0.5) > 1e-9 {
		t.Errorf("BestSingleRecall = %v, want 0.5 (best individual: 2 of 4)", cov.BestSingleRecall)
	}
}

// B catches a strict subset of what A catches → B is redundant given A.
// Dropping B loses nothing; dropping A loses vuln 2.
func TestCoverage_RedundantScanner(t *testing.T) {
	ms := newMockStore()
	coverageFixture(t, ms,
		map[int64]struct {
			tier   string
			status store.AnnotationStatus
		}{
			1: {"should", store.AnnotationStatusValid},
			2: {"should", store.AnnotationStatusValid},
			3: {"should", store.AnnotationStatusValid},
		},
		map[int64]struct {
			name   string
			caught []int64
		}{
			10: {"superset", []int64{1, 2}}, // catches both
			20: {"subset", []int64{1}},      // strict subset
		},
	)

	cov, err := NewService(ms, nil).ComputeCoverage(context.Background(), []int64{10, 20}, 1)
	if err != nil {
		t.Fatalf("ComputeCoverage: %v", err)
	}

	// subset's marginal is empty — nothing it catches that superset misses.
	if len(cov.Marginal[1].Unique) != 0 {
		t.Errorf("subset marginal = %v, want empty (redundant given superset)", vulnIDs(cov.Marginal[1].Unique))
	}
	// superset's marginal is vuln 2.
	if len(cov.Marginal[0].Unique) != 1 || cov.Marginal[0].Unique[0].ID != 2 {
		t.Errorf("superset marginal = %v, want [vuln 2]", vulnIDs(cov.Marginal[0].Unique))
	}

	// Union = superset's coverage. Running both gains nothing.
	if math.Abs(cov.UnionRecall-cov.BestSingleRecall) > 1e-9 {
		t.Errorf("UnionRecall (%v) ≠ BestSingleRecall (%v) — should be equal when one scanner dominates",
			cov.UnionRecall, cov.BestSingleRecall)
	}
}

// Three scanners, each catches one thing nobody else does + one
// pairwise overlap. This is the "suite of specialists" shape — every
// tool earns its keep, none is redundant, and the union is much better
// than any individual.
func TestCoverage_ThreeWayComplement(t *testing.T) {
	ms := newMockStore()
	coverageFixture(t, ms,
		map[int64]struct {
			tier   string
			status store.AnnotationStatus
		}{
			1: {"should", store.AnnotationStatusValid}, // only A
			2: {"should", store.AnnotationStatusValid}, // only B
			3: {"should", store.AnnotationStatusValid}, // only C
			4: {"should", store.AnnotationStatusValid}, // A+B
			5: {"should", store.AnnotationStatusValid}, // nobody
		},
		map[int64]struct {
			name   string
			caught []int64
		}{
			10: {"a", []int64{1, 4}},
			20: {"b", []int64{2, 4}},
			30: {"c", []int64{3}},
		},
	)

	cov, err := NewService(ms, nil).ComputeCoverage(context.Background(), []int64{10, 20, 30}, 1)
	if err != nil {
		t.Fatalf("ComputeCoverage: %v", err)
	}

	// Nobody catches everything — vuln 4 is A+B only, not C.
	if len(cov.CaughtByAll) != 0 {
		t.Errorf("CaughtByAll = %v, want empty (no vuln caught by all 3)", vulnIDs(cov.CaughtByAll))
	}

	// Each scanner has exactly one unique vuln.
	for i, want := range []int64{1, 2, 3} {
		if len(cov.Marginal[i].Unique) != 1 || cov.Marginal[i].Unique[0].ID != want {
			t.Errorf("Marginal[%d] = %v, want [vuln %d]", i, vulnIDs(cov.Marginal[i].Unique), want)
		}
	}

	// Union catches 4 of 5 = 0.8. Best single (A or B) catches 2 of 5 = 0.4.
	// The 2× gap is the whole point of the complement.
	if math.Abs(cov.UnionRecall-0.8) > 1e-9 {
		t.Errorf("UnionRecall = %v, want 0.8", cov.UnionRecall)
	}
	if math.Abs(cov.BestSingleRecall-0.4) > 1e-9 {
		t.Errorf("BestSingleRecall = %v, want 0.4", cov.BestSingleRecall)
	}
}

// Flaky: a scanner with 3 runs catches vuln 1 in runs 1 and 3 but not
// run 2. Coverage accounting says "caught" (generous: ≥1 hit), but the
// Flaky list flags 2/3.
func TestCoverage_FlakyDetection(t *testing.T) {
	ms := newMockStore()
	const projectID = 1
	ms.projects[projectID] = &store.CorpusProject{ID: projectID, Name: "p"}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: projectID, Status: store.AnnotationStatusValid, Category: "flaky-target"}
	ms.annotations[2] = &store.Annotation{ID: 2, ProjectID: projectID, Status: store.AnnotationStatusValid, Category: "stable-target"}

	// Scanner A: 3 iterations. Catches vuln 1 in runs 101 and 103,
	// misses in 102. Catches vuln 2 in all three.
	ms.scanners[10] = &store.Scanner{ID: 10, Name: "flaky-scanner"}
	ms.runsByScannerProject[10] = map[int64][]store.Run{projectID: {
		{ID: 101, ScannerID: 10, ProjectID: projectID, Status: store.RunStatusCompleted},
		{ID: 102, ScannerID: 10, ProjectID: projectID, Status: store.RunStatusCompleted},
		{ID: 103, ScannerID: 10, ProjectID: projectID, Status: store.RunStatusCompleted},
	}}
	ms.findingMatches[101] = []store.FindingMatch{{AnnotationID: 1}, {AnnotationID: 2}}
	ms.findingMatches[102] = []store.FindingMatch{{AnnotationID: 2}} // missed vuln 1
	ms.findingMatches[103] = []store.FindingMatch{{AnnotationID: 1}, {AnnotationID: 2}}
	for _, r := range []int64{101, 102, 103} {
		ms.unmatchedFindings[r] = []store.Finding{}
	}

	// Scanner B: single run, catches vuln 2. Gives us the second
	// scanner ComputeCoverage requires without adding noise.
	ms.scanners[20] = &store.Scanner{ID: 20, Name: "stable-scanner"}
	ms.runsByScannerProject[20] = map[int64][]store.Run{projectID: {
		{ID: 201, ScannerID: 20, ProjectID: projectID, Status: store.RunStatusCompleted},
	}}
	ms.findingMatches[201] = []store.FindingMatch{{AnnotationID: 2}}
	ms.unmatchedFindings[201] = []store.Finding{}

	cov, err := NewService(ms, nil).ComputeCoverage(context.Background(), []int64{10, 20}, projectID)
	if err != nil {
		t.Fatalf("ComputeCoverage: %v", err)
	}

	// Vuln 1 should be counted as caught (it's in flaky-scanner's
	// union-across-iterations), AND it should show up in Flaky with
	// 2/3. Vuln 2 should NOT be in Flaky — 3/3 is stable.
	found := false
	for _, f := range cov.Flaky {
		if f.Vuln.ID == 1 {
			found = true
			if f.HitRuns != 2 || f.TotalRuns != 3 {
				t.Errorf("Flaky vuln 1 = %d/%d, want 2/3", f.HitRuns, f.TotalRuns)
			}
			if f.ScannerName != "flaky-scanner" {
				t.Errorf("Flaky attributed to %q, want flaky-scanner", f.ScannerName)
			}
		}
		if f.Vuln.ID == 2 {
			t.Error("vuln 2 appears in Flaky, but it was caught 3/3 — not flaky")
		}
	}
	if !found {
		t.Error("vuln 1 missing from Flaky list despite 2/3 hit rate")
	}

	// Single-run scanner contributes no flaky entries by definition.
	for _, f := range cov.Flaky {
		if f.ScannerName == "stable-scanner" {
			t.Error("single-iteration scanner reported flaky — can't observe flake with N=1")
		}
	}
}

func TestCoverage_UnionFPCeiling(t *testing.T) {
	ms := newMockStore()
	coverageFixture(t, ms,
		map[int64]struct {
			tier   string
			status store.AnnotationStatus
		}{1: {"should", store.AnnotationStatusValid}},
		map[int64]struct {
			name   string
			caught []int64
		}{
			10: {"a", []int64{1}},
			20: {"b", []int64{1}},
		},
	)
	// A has 2 unmatched findings, B has 3. Ceiling = 5.
	ms.unmatchedFindings[1000] = []store.Finding{{ID: 1}, {ID: 2}}
	ms.unmatchedFindings[2000] = []store.Finding{{ID: 3}, {ID: 4}, {ID: 5}}

	cov, _ := NewService(ms, nil).ComputeCoverage(context.Background(), []int64{10, 20}, 1)
	if cov.UnionFPCeiling != 5 {
		t.Errorf("UnionFPCeiling = %d, want 5 (2+3)", cov.UnionFPCeiling)
	}
}

func TestCoverage_FewerThanTwoScanners(t *testing.T) {
	ms := newMockStore()
	_, err := NewService(ms, nil).ComputeCoverage(context.Background(), []int64{1}, 1)
	if err == nil {
		t.Fatal("expected error for 1 scanner — overlap needs ≥2")
	}
}

func TestCoverage_MatchedInvalidIsNotCoverage(t *testing.T) {
	// Both scanners "catch" vuln 5, but vuln 5 is a decoy (status=invalid).
	// That's a shared FALSE POSITIVE, not shared coverage. It must not
	// appear in CaughtByAll and must not inflate union recall.
	ms := newMockStore()
	coverageFixture(t, ms,
		map[int64]struct {
			tier   string
			status store.AnnotationStatus
		}{
			1: {"should", store.AnnotationStatusValid},
			5: {"should", store.AnnotationStatusInvalid},
		},
		map[int64]struct {
			name   string
			caught []int64
		}{
			10: {"a", []int64{5}}, // only the decoy
			20: {"b", []int64{5}}, // only the decoy
		},
	)

	cov, _ := NewService(ms, nil).ComputeCoverage(context.Background(), []int64{10, 20}, 1)

	if len(cov.CaughtByAll) != 0 {
		t.Errorf("CaughtByAll = %v, want empty — a shared decoy hit is not coverage", vulnIDs(cov.CaughtByAll))
	}
	if cov.UnionRecall != 0 {
		t.Errorf("UnionRecall = %v, want 0 — nobody caught a valid vuln", cov.UnionRecall)
	}
	// vuln 1 (the only valid one) is caught by nobody.
	if len(cov.CaughtByNone) != 1 || cov.CaughtByNone[0].ID != 1 {
		t.Errorf("CaughtByNone = %v, want [vuln 1]", vulnIDs(cov.CaughtByNone))
	}
}

// Tier sorting is independent of the mock (which hardcodes "should"),
// so exercise it directly on the helper.
func TestTierSort_MustBeforeShould(t *testing.T) {
	vs := []store.Vulnerability{
		{Name: "a", Criticality: "may"},
		{Name: "b", Criticality: "must"},
		{Name: "c", Criticality: "should"},
		{Name: "d", Criticality: "must"},
	}
	sortVulnsByTierThenName(vs)

	want := []string{"b", "d", "c", "a"} // must (b,d by name) → should (c) → may (a)
	for i, w := range want {
		if vs[i].Name != w {
			t.Errorf("position %d = %q, want %q (full order: %v)", i, vs[i].Name, w, vulnNames(vs))
		}
	}
}

func TestTierCount(t *testing.T) {
	vs := []store.Vulnerability{
		{Criticality: "must"}, {Criticality: "must"},
		{Criticality: "should"},
		{Criticality: "may"}, {Criticality: "may"}, {Criticality: "may"},
	}
	tc := TierCount(vs)
	if tc.Must != 2 || tc.Should != 1 || tc.May != 3 {
		t.Errorf("TierCount = %+v, want {Must:2 Should:1 May:3}", tc)
	}
}

// --- helpers ---

func vulnIDs(vs []store.Vulnerability) []int64 {
	out := make([]int64, len(vs))
	for i, v := range vs {
		out[i] = v.ID
	}
	return out
}

func vulnNames(vs []store.Vulnerability) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Name
	}
	return out
}

// The coverage fixture wires unmatchedFindings per run. The base mock
// doesn't have this map populated, so we also need to make sure the
// mock reads from it. Verify the mock setup doesn't nil-map panic.
func init() {
	// The mockStore already has unmatchedFindings as a field (used by
	// existing tests). coverageFixture sets it per run. This init is
	// a no-op, left as a breadcrumb.
	_ = sql.NullString{}
}
