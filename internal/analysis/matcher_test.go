package analysis

import (
	"database/sql"
	"math"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

func TestExactMatchSameFileSameLineSameCWE(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}

	match := matches[0]
	if match.MatchType != "exact" {
		t.Errorf("MatchType = %q, want exact", match.MatchType)
	}
	if match.Confidence.Float64 != 1.0 {
		t.Errorf("Confidence = %f, want 1.0", match.Confidence.Float64)
	}
	if match.FindingID != 1 {
		t.Errorf("FindingID = %d, want 1", match.FindingID)
	}
	if match.AnnotationID != 100 {
		t.Errorf("AnnotationID = %d, want 100", match.AnnotationID)
	}
}

func TestFuzzyMatchSameFilePlusMinus3LinesCompatibleCWE(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 45, // +3 from annotation
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-564", Valid: true}, // Same category: sql-injection
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}

	match := matches[0]
	if match.MatchType != "fuzzy" {
		t.Errorf("MatchType = %q, want fuzzy", match.MatchType)
	}
	// Distance 3, max 5 → confidence = 0.9 - (3/5)*(0.9-0.5) = 0.9 - 0.24 = 0.66
	// Allow small floating point tolerance
	expectedConfidence := 0.66
	if math.Abs(match.Confidence.Float64-expectedConfidence) > 0.01 {
		t.Errorf("Confidence = %f, want ~%f", match.Confidence.Float64, expectedConfidence)
	}
}

func TestCategoryMatchSameFilePlus15LinesSameCategory(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 57, // +15 from annotation
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-564", Valid: true}, // Same category: sql-injection
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}

	match := matches[0]
	if match.MatchType != "category" {
		t.Errorf("MatchType = %q, want category", match.MatchType)
	}
	// Distance 15, max 20 → confidence = 0.5 - (15/20)*(0.5-0.3) = 0.5 - 0.15 = 0.35
	expectedConfidence := 0.35
	if math.Abs(match.Confidence.Float64-expectedConfidence) > 0.01 {
		t.Errorf("Confidence = %f, want ~%f", match.Confidence.Float64, expectedConfidence)
	}
}

func TestNoMatchDifferentFiles(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/other.go", // Different file
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Match() returned %d matches, want 0 (different files)", len(matches))
	}
}

func TestMatchAbsoluteFindingPathBySuffix(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "/tmp/vulnerable-todoapp/routes/files.js",
		StartLine: 72,
		CWEID:     sql.NullString{String: "CWE-78", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "routes/files.js",
		StartLine: 72,
		CWEID:     sql.NullString{String: "CWE-78", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}
	if matches[0].MatchType != "exact" {
		t.Errorf("MatchType = %q, want exact", matches[0].MatchType)
	}
}

func TestNoMatchLinesTooFarApart(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 100, // 58 lines from annotation, beyond threshold
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Match() returned %d matches, want 0 (lines too far apart)", len(matches))
	}
}

func TestMultipleFindingsMultipleAnnotationsBestMatchSelection(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{
		{ID: 1, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
		{ID: 2, FilePath: "a.go", StartLine: 11, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
		{ID: 3, FilePath: "b.go", StartLine: 50, CWEID: sql.NullString{String: "CWE-79", Valid: true}},
	}
	annotations := []store.Annotation{
		{ID: 100, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},  // Exact match with finding 1
		{ID: 101, FilePath: "a.go", StartLine: 15, CWEID: sql.NullString{String: "CWE-564", Valid: true}}, // Fuzzy match with finding 2
		{ID: 102, FilePath: "b.go", StartLine: 50, CWEID: sql.NullString{String: "CWE-79", Valid: true}},  // Exact match with finding 3
	}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("Match() returned %d matches, want 3", len(matches))
	}

	// Verify each annotation matched at most once
	annotationCounts := make(map[int64]int)
	for _, m := range matches {
		annotationCounts[m.AnnotationID]++
	}
	for aID, count := range annotationCounts {
		if count > 1 {
			t.Errorf("Annotation %d matched %d times, want at most 1", aID, count)
		}
	}

	// Verify each finding matched at most once
	findingCounts := make(map[int64]int)
	for _, m := range matches {
		findingCounts[m.FindingID]++
	}
	for fID, count := range findingCounts {
		if count > 1 {
			t.Errorf("Finding %d matched %d times, want at most 1", fID, count)
		}
	}
}

func TestEachAnnotationMatchesAtMostOneFinding(t *testing.T) {
	m := NewMatcher()

	// Two findings on same line, one annotation
	findings := []store.Finding{
		{ID: 1, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
		{ID: 2, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
	}
	annotations := []store.Annotation{
		{ID: 100, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
	}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("Match() returned %d matches, want 1 (annotation can only match once)", len(matches))
	}
}

func TestEachFindingMatchesAtMostOneAnnotation(t *testing.T) {
	m := NewMatcher()

	// One finding, two annotations on same line
	findings := []store.Finding{
		{ID: 1, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
	}
	annotations := []store.Annotation{
		{ID: 100, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
		{ID: 101, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
	}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("Match() returned %d matches, want 1 (finding can only match once)", len(matches))
	}
}

func TestEmptyFindingsReturnsNoMatches(t *testing.T) {
	m := NewMatcher()

	annotations := []store.Annotation{
		{ID: 100, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
	}

	matches, err := m.Match([]store.Finding{}, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if matches == nil {
		t.Error("Match() returned nil, want empty slice")
	}
	if len(matches) != 0 {
		t.Errorf("Match() returned %d matches, want 0", len(matches))
	}
}

func TestEmptyAnnotationsReturnsNoMatches(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{
		{ID: 1, FilePath: "a.go", StartLine: 10, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
	}

	matches, err := m.Match(findings, []store.Annotation{}, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if matches == nil {
		t.Error("Match() returned nil, want empty slice")
	}
	if len(matches) != 0 {
		t.Errorf("Match() returned %d matches, want 0", len(matches))
	}
}

func TestFindingWithNoCWEMatchesByFilePlusLine(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{Valid: false}, // No CWE
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}

	match := matches[0]
	if match.MatchType != "exact" {
		t.Errorf("MatchType = %q, want exact (file+line match)", match.MatchType)
	}
}

func TestAnnotationWithNoCWEMatchesByFilePlusLine(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{Valid: false}, // No CWE
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}

	match := matches[0]
	if match.MatchType != "exact" {
		t.Errorf("MatchType = %q, want exact (file+line match)", match.MatchType)
	}
}

func TestFuzzyMatchNoCWEMatchesByProximity(t *testing.T) {
	m := NewMatcher()

	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 45, // +3 from annotation
		CWEID:     sql.NullString{Valid: false},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 42,
		CWEID:     sql.NullString{Valid: false},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}

	match := matches[0]
	if match.MatchType != "fuzzy" {
		t.Errorf("MatchType = %q, want fuzzy (proximity match)", match.MatchType)
	}
}

func TestPropagateGroups_EmitsRowForRescuedMember(t *testing.T) {
	m := NewMatcher()
	// Finding 7 matched annotation 100 directly. Annotation 101 shares
	// group 1 with 100. PropagateGroups should emit one row:
	// finding 7 → annotation 101, match_type='group'.
	direct := []store.FindingMatch{
		{FindingID: 7, AnnotationID: 100, MatchType: "exact", Confidence: sql.NullFloat64{Float64: 1.0, Valid: true}},
	}
	groups := map[int64][]int64{
		100: {1},
		101: {1},
	}

	got := m.PropagateGroups(direct, groups)
	if len(got) != 1 {
		t.Fatalf("got %d propagated rows, want 1", len(got))
	}
	g := got[0]
	if g.FindingID != 7 {
		t.Errorf("FindingID = %d, want 7 (the finding that satisfied the group)", g.FindingID)
	}
	if g.AnnotationID != 101 {
		t.Errorf("AnnotationID = %d, want 101 (the rescued member)", g.AnnotationID)
	}
	if g.MatchType != string(MatchTypeGroup) {
		t.Errorf("MatchType = %q, want %q", g.MatchType, MatchTypeGroup)
	}
	if !g.Confidence.Valid || g.Confidence.Float64 != m.GroupConfidence {
		t.Errorf("Confidence = %+v, want %v", g.Confidence, m.GroupConfidence)
	}
}

func TestPropagateGroups_SkipsDirectlyMatched(t *testing.T) {
	m := NewMatcher()
	// Both 100 and 101 are directly matched. No propagation needed — the
	// group row would be redundant with the direct match.
	direct := []store.FindingMatch{
		{FindingID: 7, AnnotationID: 100, MatchType: "exact"},
		{FindingID: 8, AnnotationID: 101, MatchType: "fuzzy"},
	}
	groups := map[int64][]int64{
		100: {1},
		101: {1},
	}

	if got := m.PropagateGroups(direct, groups); len(got) != 0 {
		t.Errorf("got %d propagated rows, want 0 (all members directly matched)", len(got))
	}
}

func TestPropagateGroups_UnsatisfiedGroupNoRows(t *testing.T) {
	m := NewMatcher()
	// 100 and 101 share group 1 but NEITHER is matched. 102 (group 2) is
	// matched. Group 1 is unsatisfied → no rows for 100 or 101.
	direct := []store.FindingMatch{
		{FindingID: 7, AnnotationID: 102, MatchType: "exact"},
	}
	groups := map[int64][]int64{
		100: {1},
		101: {1},
		102: {2},
	}

	got := m.PropagateGroups(direct, groups)
	for _, g := range got {
		if g.AnnotationID == 100 || g.AnnotationID == 101 {
			t.Errorf("propagated row for annotation %d, but its group has no matched member", g.AnnotationID)
		}
	}
}

func TestPropagateGroups_OneRowPerAnnotationEvenWithMultipleGroups(t *testing.T) {
	m := NewMatcher()
	// Annotation 101 is in two groups, both satisfied. Must emit exactly
	// one row, not one per group — the UNIQUE(finding_id, annotation_id)
	// constraint would reject the second insert anyway.
	direct := []store.FindingMatch{
		{FindingID: 7, AnnotationID: 100, MatchType: "exact"}, // satisfies group 1
		{FindingID: 8, AnnotationID: 102, MatchType: "exact"}, // satisfies group 2
	}
	groups := map[int64][]int64{
		100: {1},
		101: {1, 2}, // rescued via either
		102: {2},
	}

	got := m.PropagateGroups(direct, groups)
	count := 0
	for _, g := range got {
		if g.AnnotationID == 101 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("annotation 101 propagated %d times, want 1", count)
	}
}

func TestMatch_WideRangeTiebreak(t *testing.T) {
	m := NewMatcher()
	// One finding spanning lines 88-166 overlaps three annotations at
	// 88, 125, 140 — all same CWE, all rangeDistance=0, all exact/1.0.
	// Without a tiebreak the greedy pick is whatever sort.Slice leaves
	// first, which changes when unrelated candidates reorder the list.
	// The tiebreak must pick the annotation anchored at the finding's
	// start (88).
	findings := []store.Finding{{
		ID: 1, FilePath: "tasks.js", StartLine: 88,
		EndLine: sql.NullInt64{Int64: 166, Valid: true},
		CWEID:   sql.NullString{String: "CWE-639", Valid: true},
	}}
	annotations := []store.Annotation{
		{ID: 34, FilePath: "tasks.js", StartLine: 88, EndLine: sql.NullInt64{Int64: 94, Valid: true},
			CWEID: sql.NullString{String: "CWE-639", Valid: true}},
		{ID: 35, FilePath: "tasks.js", StartLine: 125, EndLine: sql.NullInt64{Int64: 137, Valid: true},
			CWEID: sql.NullString{String: "CWE-639", Valid: true}},
		{ID: 36, FilePath: "tasks.js", StartLine: 140, EndLine: sql.NullInt64{Int64: 149, Valid: true},
			CWEID: sql.NullString{String: "CWE-639", Valid: true}},
	}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if matches[0].AnnotationID != 34 {
		t.Errorf("matched annotation %d, want 34 (startGap=0 should win the tie)", matches[0].AnnotationID)
	}

	// Determinism: shuffled annotation order must not change the outcome.
	// This guards against accidental reversion to sort.Slice.
	annotations[0], annotations[2] = annotations[2], annotations[0]
	matches, _ = m.Match(findings, annotations, nil)
	if matches[0].AnnotationID != 34 {
		t.Errorf("after shuffle: matched %d, want 34 (tiebreak must be deterministic)", matches[0].AnnotationID)
	}
}

func TestPropagateGroups_Empties(t *testing.T) {
	m := NewMatcher()
	if got := m.PropagateGroups(nil, map[int64][]int64{100: {1}}); got != nil {
		t.Errorf("nil direct matches should yield nil, got %v", got)
	}
	if got := m.PropagateGroups([]store.FindingMatch{{FindingID: 1, AnnotationID: 100}}, nil); got != nil {
		t.Errorf("nil groups should yield nil, got %v", got)
	}
}

func TestExactMatchFindingWithinAnnotationRegion(t *testing.T) {
	m := NewMatcher()

	// Annotation spans lines 5-10, finding at line 7 → overlap → exact
	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 7,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 5,
		EndLine:   sql.NullInt64{Int64: 10, Valid: true},
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}
	if matches[0].MatchType != "exact" {
		t.Errorf("MatchType = %q, want exact (finding within annotation region)", matches[0].MatchType)
	}
	if matches[0].Confidence.Float64 != 1.0 {
		t.Errorf("Confidence = %f, want 1.0", matches[0].Confidence.Float64)
	}
}

func TestExactMatchFindingRangeOverlapsAnnotationRegion(t *testing.T) {
	m := NewMatcher()

	// Finding spans 7-12, annotation spans 10-15 → overlap at 10-12 → exact
	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 7,
		EndLine:   sql.NullInt64{Int64: 12, Valid: true},
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 10,
		EndLine:   sql.NullInt64{Int64: 15, Valid: true},
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}
	if matches[0].MatchType != "exact" {
		t.Errorf("MatchType = %q, want exact (overlapping ranges)", matches[0].MatchType)
	}
}

func TestFuzzyMatchFindingNearAnnotationEndLine(t *testing.T) {
	m := NewMatcher()

	// Annotation spans 5-10, finding at line 13 → distance is 3 (from EndLine 10) → fuzzy
	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 13,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 5,
		EndLine:   sql.NullInt64{Int64: 10, Valid: true},
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("Match() returned %d matches, want 1", len(matches))
	}
	if matches[0].MatchType != "fuzzy" {
		t.Errorf("MatchType = %q, want fuzzy (3 lines from EndLine)", matches[0].MatchType)
	}
}

func TestNoMatchFindingFarFromAnnotationRegion(t *testing.T) {
	m := NewMatcher()

	// Annotation spans 5-10, finding at line 50 → distance 40 → no match
	findings := []store.Finding{{
		ID:        1,
		FilePath:  "src/main.go",
		StartLine: 50,
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}
	annotations := []store.Annotation{{
		ID:        100,
		FilePath:  "src/main.go",
		StartLine: 5,
		EndLine:   sql.NullInt64{Int64: 10, Valid: true},
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}}

	matches, err := m.Match(findings, annotations, nil)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Match() returned %d matches, want 0", len(matches))
	}
}

func TestRangeDistance(t *testing.T) {
	tests := []struct {
		name                       string
		aStart, aEnd, bStart, bEnd int
		want                       int
	}{
		{"identical points", 10, 10, 10, 10, 0},
		{"overlapping ranges", 5, 10, 8, 15, 0},
		{"contained range", 5, 20, 8, 12, 0},
		{"adjacent ranges", 5, 10, 11, 15, 1},
		{"gap between ranges", 5, 10, 15, 20, 5},
		{"reversed order gap", 15, 20, 5, 10, 5},
		{"touching at endpoint", 5, 10, 10, 15, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rangeDistance(tt.aStart, tt.aEnd, tt.bStart, tt.bEnd)
			if got != tt.want {
				t.Errorf("rangeDistance(%d,%d,%d,%d) = %d, want %d",
					tt.aStart, tt.aEnd, tt.bStart, tt.bEnd, got, tt.want)
			}
		})
	}
}

func TestConfidenceCalculation(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name          string
		lineOffset    int
		findingCWE    string
		annotationCWE string
		wantType      string
		wantConf      float64
	}{
		{"exact same CWE", 0, "CWE-89", "CWE-89", "exact", 1.0},
		// CWE normalization: these would fail a byte-for-byte string compare.
		{"exact despite suffix", 0, "CWE-89: SQL Injection", "CWE-89", "exact", 1.0},
		{"exact despite case", 0, "cwe-89", "CWE-89", "exact", 1.0},
		// Hierarchy tier: same line, CWE-related. 564 is a direct child of 89
		// in View 1000, so tree distance 1 → 0.95. Previously this was "fuzzy"
		// at 0.9 — same location with a parent-CWE is a stronger signal than
		// the fuzzy tier gave it credit for.
		{"hierarchy parent-child", 0, "CWE-89", "CWE-564", "hierarchy", 0.95},
		// The sample-app drift pairs land here too. 639↔862 is curated → dist 1.
		{"hierarchy curated pair", 0, "CWE-862", "CWE-639", "hierarchy", 0.95},
		// 915↔269 (mass-assignment vs priv-esc): unrelated in MITRE's tree
		// (different pillars), only linked by the curated list → dist 1.
		{"hierarchy curated only", 0, "CWE-915", "CWE-269", "hierarchy", 0.95},
		// Fuzzy tier at nonzero line distance — CWE-related, nearby code.
		{"fuzzy distance 1", 1, "CWE-89", "CWE-564", "fuzzy", 0.82},        // 0.9 - (1/5)*(0.9-0.5) = 0.82
		{"fuzzy distance 5", 5, "CWE-89", "CWE-564", "fuzzy", 0.5},         // 0.9 - (5/5)*(0.9-0.5) = 0.5
		{"category distance 10", 10, "CWE-89", "CWE-564", "category", 0.4}, // 0.5 - (10/20)*(0.5-0.3) = 0.4
		{"category distance 20", 20, "CWE-89", "CWE-564", "category", 0.3}, // 0.5 - (20/20)*(0.5-0.3) = 0.3
		// same_line fallback: same location, CWE completely unrelated in
		// tree+category+curated. 798 (hardcoded creds) and 362 (race
		// condition) share no ancestor below the pillars and no category.
		// This tier is increasingly rare with the hierarchy walker —
		// most "unrelated" CWEs turn out to share a MITRE category.
		{"same_line unrelated", 0, "CWE-798", "CWE-362", "same_line", 0.2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []store.Finding{{
				ID:        1,
				FilePath:  "a.go",
				StartLine: 10 + tt.lineOffset,
				CWEID:     sql.NullString{String: tt.findingCWE, Valid: true},
			}}
			annotations := []store.Annotation{{
				ID:        100,
				FilePath:  "a.go",
				StartLine: 10,
				CWEID:     sql.NullString{String: tt.annotationCWE, Valid: true},
			}}

			matches, err := m.Match(findings, annotations, nil)
			if err != nil {
				t.Fatalf("Match() error: %v", err)
			}
			if len(matches) != 1 {
				t.Fatalf("Match() returned %d matches, want 1", len(matches))
			}

			match := matches[0]
			if match.MatchType != tt.wantType {
				t.Errorf("MatchType = %q, want %q", match.MatchType, tt.wantType)
			}
			if math.Abs(match.Confidence.Float64-tt.wantConf) > 0.01 {
				t.Errorf("Confidence = %f, want ~%f", match.Confidence.Float64, tt.wantConf)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain relative", "routes/api.js", "routes/api.js"},
		{"dot-slash prefix", "./routes/api.js", "routes/api.js"},
		{"target mount", "/target/routes/api.js", "routes/api.js"},
		{"src mount", "/src/routes/api.js", "routes/api.js"},
		{"app mount", "/app/routes/api.js", "routes/api.js"},
		{"absolute no mount", "/usr/local/routes/api.js", "usr/local/routes/api.js"},
		{"dot-dot segment", "src/../routes/api.js", "routes/api.js"},
		{"dot segment", "src/./routes/api.js", "src/routes/api.js"},
		{"trailing slash", "routes/api/", "routes/api"},
		{"backslash separators", "src\\routes\\api.js", "src/routes/api.js"},
		{"mixed separators", "src/routes\\api.js", "src/routes/api.js"},
		{"double slash", "src//routes/api.js", "src/routes/api.js"},
		{"target with dot-dot", "/target/src/../routes/api.js", "routes/api.js"},
		{"bare dot", ".", "."},
		{"empty string", "", "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePath(tt.in)
			if got != tt.want {
				t.Errorf("normalizePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
