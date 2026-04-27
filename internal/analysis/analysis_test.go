package analysis

import (
	"context"
	"database/sql"
	"math"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

type mockStore struct {
	runs                 map[int64]*store.Run
	findings             map[int64][]store.Finding
	findingMatches       map[int64][]store.FindingMatch
	unmatchedFindings    map[int64][]store.Finding
	unmatchedAnnotations map[int64][]store.Annotation
	annotations          map[int64]*store.Annotation
	scanners             map[int64]*store.Scanner
	projects             map[int64]*store.CorpusProject
	experiments          map[int64]*store.Experiment
	expScanners          map[int64][]store.Scanner
	expProjects          map[int64][]store.CorpusProject
	runsByScannerProject map[int64]map[int64][]store.Run
}

func newMockStore() *mockStore {
	return &mockStore{
		runs:                 make(map[int64]*store.Run),
		findings:             make(map[int64][]store.Finding),
		findingMatches:       make(map[int64][]store.FindingMatch),
		unmatchedFindings:    make(map[int64][]store.Finding),
		unmatchedAnnotations: make(map[int64][]store.Annotation),
		annotations:          make(map[int64]*store.Annotation),
		scanners:             make(map[int64]*store.Scanner),
		projects:             make(map[int64]*store.CorpusProject),
		experiments:          make(map[int64]*store.Experiment),
		expScanners:          make(map[int64][]store.Scanner),
		expProjects:          make(map[int64][]store.CorpusProject),
		runsByScannerProject: make(map[int64]map[int64][]store.Run),
	}
}

func (m *mockStore) GetRun(ctx context.Context, id int64) (*store.Run, error) {
	r, ok := m.runs[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return r, nil
}

func (m *mockStore) GetAnnotation(ctx context.Context, id int64) (*store.Annotation, error) {
	a, ok := m.annotations[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return a, nil
}

func (m *mockStore) GetFinding(ctx context.Context, id int64) (*store.Finding, error) {
	for _, findings := range m.findings {
		for _, f := range findings {
			if f.ID == id {
				return &f, nil
			}
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) ListFindingsByRun(ctx context.Context, runID int64) ([]store.Finding, error) {
	return m.findings[runID], nil
}

func (m *mockStore) ListFindingMatchesByRun(ctx context.Context, runID int64) ([]store.FindingMatch, error) {
	return m.findingMatches[runID], nil
}

func (m *mockStore) ListUnmatchedFindings(ctx context.Context, runID int64) ([]store.Finding, error) {
	return m.unmatchedFindings[runID], nil
}

func (m *mockStore) ListUnmatchedAnnotations(ctx context.Context, runID, projectID int64) ([]store.Annotation, error) {
	key := runID*1000 + projectID // Simple composite key for test
	return m.unmatchedAnnotations[key], nil
}

func (m *mockStore) ListAnnotationsByProject(ctx context.Context, projectID int64) ([]store.Annotation, error) {
	var result []store.Annotation
	for _, a := range m.annotations {
		if a.ProjectID == projectID {
			result = append(result, *a)
		}
	}
	return result, nil
}

func (m *mockStore) ListRunsByExperiment(ctx context.Context, experimentID int64) ([]store.Run, error) {
	var result []store.Run
	for _, r := range m.runs {
		if r.ExperimentID == experimentID {
			result = append(result, *r)
		}
	}
	return result, nil
}

func (m *mockStore) GetExperiment(ctx context.Context, id int64) (*store.Experiment, error) {
	e, ok := m.experiments[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return e, nil
}

func (m *mockStore) ListExperimentScanners(ctx context.Context, experimentID int64) ([]store.Scanner, error) {
	return m.expScanners[experimentID], nil
}

func (m *mockStore) ListExperimentProjects(ctx context.Context, experimentID int64) ([]store.CorpusProject, error) {
	return m.expProjects[experimentID], nil
}

func (m *mockStore) GetScanner(ctx context.Context, id int64) (*store.Scanner, error) {
	s, ok := m.scanners[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return s, nil
}

func (m *mockStore) GetProject(ctx context.Context, id int64) (*store.CorpusProject, error) {
	p, ok := m.projects[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return p, nil
}

func (m *mockStore) ListRunsByScannerProject(ctx context.Context, scannerID, projectID int64) ([]store.Run, error) {
	if sp, ok := m.runsByScannerProject[scannerID]; ok {
		return sp[projectID], nil
	}
	return nil, nil
}

func (m *mockStore) CreateFindingMatch(ctx context.Context, fm *store.FindingMatch) (int64, error) {
	runID := int64(0)
	// Find the run for this finding
	for rid, findings := range m.findings {
		for _, f := range findings {
			if f.ID == fm.FindingID {
				runID = rid
				break
			}
		}
	}
	fm.ID = int64(len(m.findingMatches[runID]) + 1)
	m.findingMatches[runID] = append(m.findingMatches[runID], *fm)
	return fm.ID, nil
}

func (m *mockStore) ListDispositionsByRun(ctx context.Context, runID int64) ([]store.FindingDisposition, error) {
	return nil, nil
}

func (m *mockStore) CreateAnnotation(ctx context.Context, a *store.Annotation) (int64, error) {
	a.ID = int64(len(m.annotations) + 1)
	m.annotations[a.ID] = a
	return a.ID, nil
}

func (m *mockStore) ListAllGroupMembersByProject(ctx context.Context, projectID int64) ([]store.AnnotationGroupMember, error) {
	return nil, nil
}

func (m *mockStore) StampRunScorer(ctx context.Context, runID int64, matcherVersion, annotationHash string) error {
	if r, ok := m.runs[runID]; ok {
		r.MatcherVersion = sql.NullString{String: matcherVersion, Valid: true}
		r.AnnotationHash = sql.NullString{String: annotationHash, Valid: true}
	}
	return nil
}

// Vuln-model methods: synthesize from the mock's annotations map so the
// existing per-annotation test fixtures keep working under vuln-level
// accounting. Each mock annotation becomes a one-evidence vuln — the
// degenerate case where old and new counting agree. Tests that want
// multi-evidence behaviour set up store.Vulnerability fixtures directly.

func (m *mockStore) ListEvidenceByProject(ctx context.Context, projectID int64) ([]store.Evidence, error) {
	out := []store.Evidence{}
	for _, a := range m.annotations {
		if a.ProjectID != projectID {
			continue
		}
		out = append(out, store.Evidence{
			ID: a.ID, VulnID: a.ID, // solo: evidence.id == vuln.id
			FilePath: a.FilePath, StartLine: a.StartLine, EndLine: a.EndLine,
			Role: "sink", Category: a.Category, Severity: a.Severity,
		})
	}
	return out, nil
}

func (m *mockStore) ListVulnCWEs(ctx context.Context, projectID int64) (map[int64][]string, error) {
	out := map[int64][]string{}
	for _, a := range m.annotations {
		if a.ProjectID == projectID && a.CWEID.Valid && a.CWEID.String != "" {
			out[a.ID] = []string{a.CWEID.String}
		}
	}
	return out, nil
}

func (m *mockStore) annotationToVuln(a *store.Annotation) store.Vulnerability {
	return store.Vulnerability{
		ID: a.ID, ProjectID: a.ProjectID, Name: a.Category,
		Description: a.Description, Criticality: "should", Status: string(a.Status),
	}
}

func (m *mockStore) ListVulnerabilitiesByProject(ctx context.Context, projectID int64) ([]store.Vulnerability, error) {
	out := []store.Vulnerability{}
	for _, a := range m.annotations {
		if a.ProjectID == projectID {
			out = append(out, m.annotationToVuln(a))
		}
	}
	return out, nil
}

func (m *mockStore) ListSatisfiedVulns(ctx context.Context, runID, projectID int64) ([]store.Vulnerability, error) {
	matched := map[int64]bool{}
	for _, fm := range m.findingMatches[runID] {
		matched[fm.AnnotationID] = true
	}
	out := []store.Vulnerability{}
	for _, a := range m.annotations {
		if a.ProjectID == projectID && matched[a.ID] {
			out = append(out, m.annotationToVuln(a))
		}
	}
	return out, nil
}

func (m *mockStore) VulnConsensus(ctx context.Context, projectID int64) (map[int64]int, error) {
	// Mock annotations don't track annotators; everything has consensus 1.
	out := map[int64]int{}
	for _, a := range m.annotations {
		if a.ProjectID == projectID {
			out[a.ID] = 1
		}
	}
	return out, nil
}

func (m *mockStore) ListUnsatisfiedVulns(ctx context.Context, runID, projectID int64) ([]store.Vulnerability, error) {
	matched := map[int64]bool{}
	for _, fm := range m.findingMatches[runID] {
		matched[fm.AnnotationID] = true
	}
	out := []store.Vulnerability{}
	for _, a := range m.annotations {
		if a.ProjectID == projectID && !matched[a.ID] {
			out = append(out, m.annotationToVuln(a))
		}
	}
	return out, nil
}

func TestAnalyzeRunMatchesFindingsAndReturnsMetrics(t *testing.T) {
	ms := newMockStore()

	// Setup: run with 2 TP, 1 FP (unmatched), 1 FN
	ms.runs[1] = &store.Run{
		ID:              1,
		ProjectID:       100,
		Status:          store.RunStatusCompleted,
		DurationMs:      sql.NullInt64{Int64: 1500, Valid: true},
		MemoryPeakBytes: sql.NullInt64{Int64: 50000000, Valid: true},
	}

	ms.findingMatches[1] = []store.FindingMatch{
		{ID: 1, FindingID: 10, AnnotationID: 1},
		{ID: 2, FindingID: 11, AnnotationID: 2},
	}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 100, Status: store.AnnotationStatusValid, Category: "sql-injection"}
	ms.annotations[2] = &store.Annotation{ID: 2, ProjectID: 100, Status: store.AnnotationStatusValid, Category: "xss"}
	// FN: annotation 3 exists but has no match. Pre-010 the test stuffed
	// this directly into unmatchedAnnotations; the vuln-path mock derives
	// unsatisfied vulns from the annotations map + the match map, so it
	// needs to see the annotation.
	ms.annotations[3] = &store.Annotation{ID: 3, ProjectID: 100, Status: store.AnnotationStatusValid, Category: "idor"}

	ms.unmatchedFindings[1] = []store.Finding{{ID: 12}}
	ms.unmatchedAnnotations[1*1000+100] = []store.Annotation{{ID: 3, Status: store.AnnotationStatusValid}}

	svc := NewService(ms, nil)
	ctx := context.Background()

	metrics, err := svc.AnalyzeRun(ctx, 1)
	if err != nil {
		t.Fatalf("AnalyzeRun() error: %v", err)
	}

	if metrics.TP != 2 {
		t.Errorf("TP = %d, want 2", metrics.TP)
	}
	if metrics.FP != 1 {
		t.Errorf("FP = %d, want 1", metrics.FP)
	}
	if metrics.FN != 1 {
		t.Errorf("FN = %d, want 1", metrics.FN)
	}
	if metrics.DurationMs != 1500 {
		t.Errorf("DurationMs = %d, want 1500", metrics.DurationMs)
	}
	if metrics.MemoryPeakBytes != 50000000 {
		t.Errorf("MemoryPeakBytes = %d, want 50000000", metrics.MemoryPeakBytes)
	}

	// Precision = 2/(2+1) = 0.666...
	expectedPrecision := 2.0 / 3.0
	if math.Abs(metrics.Precision-expectedPrecision) > 0.001 {
		t.Errorf("Precision = %f, want %f", metrics.Precision, expectedPrecision)
	}

	// Recall = 2/(2+1) = 0.666...
	expectedRecall := 2.0 / 3.0
	if math.Abs(metrics.Recall-expectedRecall) > 0.001 {
		t.Errorf("Recall = %f, want %f", metrics.Recall, expectedRecall)
	}
}

func TestAnalyzeExperimentAggregatesAcrossScannerAndProject(t *testing.T) {
	ms := newMockStore()

	// Two scanners, two projects
	ms.scanners[1] = &store.Scanner{ID: 1, Name: "semgrep"}
	ms.scanners[2] = &store.Scanner{ID: 2, Name: "codeql"}
	ms.projects[1] = &store.CorpusProject{ID: 1, Name: "project-a"}
	ms.projects[2] = &store.CorpusProject{ID: 2, Name: "project-b"}

	ms.experiments[1] = &store.Experiment{ID: 1, Name: "exp1"}

	// Runs: semgrep/project-a, codeql/project-a
	ms.runs[1] = &store.Run{ID: 1, ExperimentID: 1, ScannerID: 1, ProjectID: 1, Status: store.RunStatusCompleted}
	ms.runs[2] = &store.Run{ID: 2, ExperimentID: 1, ScannerID: 2, ProjectID: 1, Status: store.RunStatusCompleted}

	// Matches for run 1: 3 TP
	ms.findingMatches[1] = []store.FindingMatch{
		{ID: 1, FindingID: 1, AnnotationID: 1},
		{ID: 2, FindingID: 2, AnnotationID: 2},
		{ID: 3, FindingID: 3, AnnotationID: 3},
	}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.annotations[2] = &store.Annotation{ID: 2, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.annotations[3] = &store.Annotation{ID: 3, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[1] = []store.Finding{}
	ms.unmatchedAnnotations[1*1000+1] = []store.Annotation{}

	// Matches for run 2: 2 TP, 1 FP
	ms.findingMatches[2] = []store.FindingMatch{
		{ID: 4, FindingID: 4, AnnotationID: 4},
		{ID: 5, FindingID: 5, AnnotationID: 5},
	}
	ms.annotations[4] = &store.Annotation{ID: 4, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.annotations[5] = &store.Annotation{ID: 5, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[2] = []store.Finding{{ID: 6}}
	ms.unmatchedAnnotations[2*1000+1] = []store.Annotation{}

	svc := NewService(ms, nil)
	ctx := context.Background()

	result, err := svc.AnalyzeExperiment(ctx, 1)
	if err != nil {
		t.Fatalf("AnalyzeExperiment() error: %v", err)
	}

	// Check semgrep results
	semgrep, ok := result["semgrep"]
	if !ok {
		t.Fatal("Expected semgrep in result")
	}
	projectA, ok := semgrep["project-a"]
	if !ok {
		t.Fatal("Expected project-a for semgrep")
	}
	if projectA.TP != 3 {
		t.Errorf("semgrep/project-a TP = %d, want 3", projectA.TP)
	}

	// Check codeql results
	codeql, ok := result["codeql"]
	if !ok {
		t.Fatal("Expected codeql in result")
	}
	projectACQ, ok := codeql["project-a"]
	if !ok {
		t.Fatal("Expected project-a for codeql")
	}
	if projectACQ.TP != 2 {
		t.Errorf("codeql/project-a TP = %d, want 2", projectACQ.TP)
	}
	if projectACQ.FP != 1 {
		t.Errorf("codeql/project-a FP = %d, want 1", projectACQ.FP)
	}
}

func TestAnalyzeRunWithCategories(t *testing.T) {
	ms := newMockStore()

	ms.runs[1] = &store.Run{ID: 1, ProjectID: 100, Status: store.RunStatusCompleted}

	ms.findingMatches[1] = []store.FindingMatch{
		{ID: 1, FindingID: 10, AnnotationID: 1},
		{ID: 2, FindingID: 11, AnnotationID: 2},
	}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 100, Status: store.AnnotationStatusValid, Category: "sql-injection"}
	ms.annotations[2] = &store.Annotation{ID: 2, ProjectID: 100, Status: store.AnnotationStatusValid, Category: "xss"}
	ms.unmatchedFindings[1] = []store.Finding{}
	ms.unmatchedAnnotations[1*1000+100] = []store.Annotation{}

	svc := NewService(ms, nil)
	ctx := context.Background()

	metrics, categoryMetrics, err := svc.AnalyzeRunWithCategories(ctx, 1)
	if err != nil {
		t.Fatalf("AnalyzeRunWithCategories() error: %v", err)
	}

	if metrics.TP != 2 {
		t.Errorf("TP = %d, want 2", metrics.TP)
	}

	if len(categoryMetrics) != 2 {
		t.Fatalf("categoryMetrics count = %d, want 2", len(categoryMetrics))
	}

	sqlInj, ok := categoryMetrics["sql-injection"]
	if !ok {
		t.Fatal("Expected sql-injection category")
	}
	if sqlInj.TP != 1 {
		t.Errorf("sql-injection TP = %d, want 1", sqlInj.TP)
	}

	xss, ok := categoryMetrics["xss"]
	if !ok {
		t.Fatal("Expected xss category")
	}
	if xss.TP != 1 {
		t.Errorf("xss TP = %d, want 1", xss.TP)
	}
}

func TestAnalyzeExperimentSkipsNonCompletedRuns(t *testing.T) {
	ms := newMockStore()

	ms.scanners[1] = &store.Scanner{ID: 1, Name: "semgrep"}
	ms.projects[1] = &store.CorpusProject{ID: 1, Name: "project-a"}
	ms.experiments[1] = &store.Experiment{ID: 1, Name: "exp1"}

	// Two runs: one completed, one pending
	ms.runs[1] = &store.Run{ID: 1, ExperimentID: 1, ScannerID: 1, ProjectID: 1, Status: store.RunStatusCompleted}
	ms.runs[2] = &store.Run{ID: 2, ExperimentID: 1, ScannerID: 1, ProjectID: 1, Status: store.RunStatusPending}

	ms.findingMatches[1] = []store.FindingMatch{
		{ID: 1, FindingID: 1, AnnotationID: 1},
	}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[1] = []store.Finding{}
	ms.unmatchedAnnotations[1*1000+1] = []store.Annotation{}

	svc := NewService(ms, nil)
	ctx := context.Background()

	result, err := svc.AnalyzeExperiment(ctx, 1)
	if err != nil {
		t.Fatalf("AnalyzeExperiment() error: %v", err)
	}

	// Should only have one result (from completed run)
	if len(result) != 1 {
		t.Fatalf("Expected 1 scanner result, got %d", len(result))
	}
	if len(result["semgrep"]) != 1 {
		t.Fatalf("Expected 1 project for semgrep, got %d", len(result["semgrep"]))
	}
}

func TestCompareScannerReturnsDeltas(t *testing.T) {
	ms := newMockStore()

	ms.scanners[1] = &store.Scanner{ID: 1, Name: "semgrep"}
	ms.scanners[2] = &store.Scanner{ID: 2, Name: "codeql"}
	ms.projects[1] = &store.CorpusProject{ID: 1, Name: "project-a"}

	// Setup runs for both scanners on same project
	ms.runs[1] = &store.Run{ID: 1, ScannerID: 1, ProjectID: 1, Status: store.RunStatusCompleted, DurationMs: sql.NullInt64{Int64: 1000, Valid: true}}
	ms.runs[2] = &store.Run{ID: 2, ScannerID: 2, ProjectID: 1, Status: store.RunStatusCompleted, DurationMs: sql.NullInt64{Int64: 2000, Valid: true}}

	// semgrep: 2 TP, 0 FP, 0 FN → P=1.0, R=1.0, F1=1.0
	ms.findingMatches[1] = []store.FindingMatch{
		{ID: 1, FindingID: 1, AnnotationID: 1},
		{ID: 2, FindingID: 2, AnnotationID: 2},
	}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.annotations[2] = &store.Annotation{ID: 2, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[1] = []store.Finding{}
	ms.unmatchedAnnotations[1*1000+1] = []store.Annotation{}

	// codeql: 1 TP, 1 FP, 1 FN → P=0.5, R=0.5, F1=0.5
	ms.findingMatches[2] = []store.FindingMatch{
		{ID: 3, FindingID: 3, AnnotationID: 3},
	}
	ms.annotations[3] = &store.Annotation{ID: 3, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[2] = []store.Finding{{ID: 4}}
	ms.unmatchedAnnotations[2*1000+1] = []store.Annotation{{ID: 4, Status: store.AnnotationStatusValid}}

	ms.runsByScannerProject[1] = map[int64][]store.Run{1: {*ms.runs[1]}}
	ms.runsByScannerProject[2] = map[int64][]store.Run{1: {*ms.runs[2]}}

	svc := NewService(ms, nil)
	ctx := context.Background()

	mc, err := svc.CompareScanners(ctx, []int64{1, 2}, 1)
	if err != nil {
		t.Fatalf("CompareScanners() error: %v", err)
	}

	if mc.Entries[0].ScannerName != "semgrep" {
		t.Errorf("Entries[0] = %s, want semgrep", mc.Entries[0].ScannerName)
	}
	if mc.Entries[1].ScannerName != "codeql" {
		t.Errorf("Entries[1] = %s, want codeql", mc.Entries[1].ScannerName)
	}

	// codeql.Precision (0.5) - semgrep.Precision (1.0) = -0.5
	expectedPrecisionDelta := -0.5
	if math.Abs(mc.Entries[1].Delta.Precision-expectedPrecisionDelta) > 0.001 {
		t.Errorf("PrecisionDelta = %f, want %f", mc.Entries[1].Delta.Precision, expectedPrecisionDelta)
	}

	// DurationDelta = 2000 - 1000 = 1000
	if mc.Entries[1].Delta.DurationDeltaMs != 1000 {
		t.Errorf("DurationDeltaMs = %d, want 1000", mc.Entries[1].Delta.DurationDeltaMs)
	}
}

func TestCompareScanners_MultipleEntries(t *testing.T) {
	ms := newMockStore()

	ms.scanners[1] = &store.Scanner{ID: 1, Name: "semgrep", Version: "1.0.0"}
	ms.scanners[2] = &store.Scanner{ID: 2, Name: "codeql", Version: "2.0.0"}
	ms.scanners[3] = &store.Scanner{ID: 3, Name: "snyk", Version: "3.0.0"}
	ms.projects[1] = &store.CorpusProject{ID: 1, Name: "project-a"}

	// semgrep: 2 TP, 0 FP, 0 FN → P=1.0, R=1.0, F1=1.0
	ms.runs[1] = &store.Run{ID: 1, ScannerID: 1, ProjectID: 1, Status: store.RunStatusCompleted, DurationMs: sql.NullInt64{Int64: 1000, Valid: true}}
	ms.findingMatches[1] = []store.FindingMatch{
		{ID: 1, FindingID: 1, AnnotationID: 1},
		{ID: 2, FindingID: 2, AnnotationID: 2},
	}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.annotations[2] = &store.Annotation{ID: 2, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[1] = []store.Finding{}
	ms.unmatchedAnnotations[1*1000+1] = []store.Annotation{}

	// codeql: 1 TP, 1 FP, 1 FN → P=0.5, R=0.5
	ms.runs[2] = &store.Run{ID: 2, ScannerID: 2, ProjectID: 1, Status: store.RunStatusCompleted, DurationMs: sql.NullInt64{Int64: 2000, Valid: true}}
	ms.findingMatches[2] = []store.FindingMatch{
		{ID: 3, FindingID: 3, AnnotationID: 3},
	}
	ms.annotations[3] = &store.Annotation{ID: 3, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[2] = []store.Finding{{ID: 4}}
	ms.unmatchedAnnotations[2*1000+1] = []store.Annotation{{ID: 4, Status: store.AnnotationStatusValid}}

	// snyk: 2 TP, 2 FP, 0 FN → P=0.5, R=1.0
	ms.runs[3] = &store.Run{ID: 3, ScannerID: 3, ProjectID: 1, Status: store.RunStatusCompleted, DurationMs: sql.NullInt64{Int64: 3000, Valid: true}}
	ms.findingMatches[3] = []store.FindingMatch{
		{ID: 6, FindingID: 6, AnnotationID: 5},
		{ID: 7, FindingID: 7, AnnotationID: 6},
	}
	ms.annotations[5] = &store.Annotation{ID: 5, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.annotations[6] = &store.Annotation{ID: 6, ProjectID: 1, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[3] = []store.Finding{{ID: 8}, {ID: 9}}
	ms.unmatchedAnnotations[3*1000+1] = []store.Annotation{}

	ms.runsByScannerProject[1] = map[int64][]store.Run{1: {*ms.runs[1]}}
	ms.runsByScannerProject[2] = map[int64][]store.Run{1: {*ms.runs[2]}}
	ms.runsByScannerProject[3] = map[int64][]store.Run{1: {*ms.runs[3]}}

	svc := NewService(ms, nil)
	ctx := context.Background()

	mc, err := svc.CompareScanners(ctx, []int64{1, 2, 3}, 1)
	if err != nil {
		t.Fatalf("CompareScanners() error: %v", err)
	}

	if mc.ProjectName != "project-a" {
		t.Errorf("ProjectName = %s, want project-a", mc.ProjectName)
	}
	if mc.ProjectID != 1 {
		t.Errorf("ProjectID = %d, want 1", mc.ProjectID)
	}
	if mc.BaselineIndex != 0 {
		t.Errorf("BaselineIndex = %d, want 0", mc.BaselineIndex)
	}
	if len(mc.Entries) != 3 {
		t.Fatalf("len(Entries) = %d, want 3", len(mc.Entries))
	}

	// Baseline (semgrep) should have no delta
	if mc.Entries[0].ScannerName != "semgrep" {
		t.Errorf("Entries[0].ScannerName = %s, want semgrep", mc.Entries[0].ScannerName)
	}
	if mc.Entries[0].Delta != nil {
		t.Errorf("Entries[0].Delta should be nil for baseline")
	}
	if mc.Entries[0].ScannerVersion != "1.0.0" {
		t.Errorf("Entries[0].ScannerVersion = %s, want 1.0.0", mc.Entries[0].ScannerVersion)
	}
	if mc.Entries[0].RunID != 1 {
		t.Errorf("Entries[0].RunID = %d, want 1", mc.Entries[0].RunID)
	}

	// codeql delta vs semgrep: P = 0.5 - 1.0 = -0.5
	if mc.Entries[1].Delta == nil {
		t.Fatal("Entries[1].Delta should not be nil")
	}
	if math.Abs(mc.Entries[1].Delta.Precision-(-0.5)) > 0.001 {
		t.Errorf("Entries[1].Delta.Precision = %f, want -0.5", mc.Entries[1].Delta.Precision)
	}
	if mc.Entries[1].Delta.DurationDeltaMs != 1000 {
		t.Errorf("Entries[1].Delta.DurationDeltaMs = %d, want 1000", mc.Entries[1].Delta.DurationDeltaMs)
	}

	// snyk delta vs semgrep: P = 0.5 - 1.0 = -0.5, R = 1.0 - 1.0 = 0.0
	if mc.Entries[2].Delta == nil {
		t.Fatal("Entries[2].Delta should not be nil")
	}
	if math.Abs(mc.Entries[2].Delta.Precision-(-0.5)) > 0.001 {
		t.Errorf("Entries[2].Delta.Precision = %f, want -0.5", mc.Entries[2].Delta.Precision)
	}
	if math.Abs(mc.Entries[2].Delta.Recall-0.0) > 0.001 {
		t.Errorf("Entries[2].Delta.Recall = %f, want 0.0", mc.Entries[2].Delta.Recall)
	}
	if mc.Entries[2].Delta.DurationDeltaMs != 2000 {
		t.Errorf("Entries[2].Delta.DurationDeltaMs = %d, want 2000", mc.Entries[2].Delta.DurationDeltaMs)
	}
}

func TestCompareScanners_TooFewScanners(t *testing.T) {
	ms := newMockStore()
	svc := NewService(ms, nil)
	ctx := context.Background()

	_, err := svc.CompareScanners(ctx, []int64{1}, 1)
	if err == nil {
		t.Fatal("expected error for fewer than 2 scanners")
	}
}

// TestCanaryMatchRunComputesAndPersistsMatches is a canary test that verifies
// the full matching pipeline: findings + annotations → Matcher → persisted matches → metrics.
// This ensures MatchRun actually calls the Matcher and stores results,
// rather than relying on pre-populated finding_matches.
// Findings use /target/ prefixed paths (as scanners report from inside Docker),
// while annotations use relative paths — the matcher must normalize both.
func TestCanaryMatchRunComputesAndPersistsMatches(t *testing.T) {
	ms := newMockStore()

	// Setup: a run with findings and annotations but NO pre-populated matches.
	// The matcher should compute matches from scratch.
	ms.runs[1] = &store.Run{
		ID:        1,
		ProjectID: 100,
		Status:    store.RunStatusCompleted,
	}

	// Findings that the scanner produced — note /target/ prefix from Docker mount
	ms.findings[1] = []store.Finding{
		{ID: 10, RunID: 1, FilePath: "/target/routes/login.ts", StartLine: 34, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
		{ID: 11, RunID: 1, FilePath: "/target/routes/search.ts", StartLine: 23, CWEID: sql.NullString{String: "CWE-89", Valid: true}},
		{ID: 12, RunID: 1, FilePath: "/target/routes/unrelated.ts", StartLine: 1}, // no matching annotation → FP
	}

	// Annotations (ground truth) for the project — relative paths
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 100, FilePath: "routes/login.ts", StartLine: 34, CWEID: sql.NullString{String: "CWE-89", Valid: true}, Status: store.AnnotationStatusValid, Category: "sql-injection"}
	ms.annotations[2] = &store.Annotation{ID: 2, ProjectID: 100, FilePath: "routes/search.ts", StartLine: 23, CWEID: sql.NullString{String: "CWE-89", Valid: true}, Status: store.AnnotationStatusValid, Category: "sql-injection"}
	ms.annotations[3] = &store.Annotation{ID: 3, ProjectID: 100, FilePath: "routes/b2bOrder.ts", StartLine: 23, CWEID: sql.NullString{String: "CWE-94", Valid: true}, Status: store.AnnotationStatusValid, Category: "code-injection"} // no finding → FN

	// No pre-populated findingMatches — MatchRun must compute them.
	// No pre-populated unmatchedFindings/unmatchedAnnotations — those come from the store queries.
	// For the mock we need to simulate what the real store returns after matches are inserted.

	// unmatchedFindings: finding 12 has no annotation match
	ms.unmatchedFindings[1] = []store.Finding{
		{ID: 12, RunID: 1, FilePath: "routes/unrelated.ts", StartLine: 1},
	}
	// unmatchedAnnotations: annotation 3 has no finding match
	ms.unmatchedAnnotations[1*1000+100] = []store.Annotation{
		{ID: 3, ProjectID: 100, FilePath: "routes/b2bOrder.ts", StartLine: 23, Status: store.AnnotationStatusValid},
	}

	svc := NewService(ms, nil)
	ctx := context.Background()

	// MatchRun should compute matches and persist them
	if err := svc.MatchRun(ctx, 1); err != nil {
		t.Fatalf("MatchRun() error: %v", err)
	}

	// Verify matches were persisted
	matches := ms.findingMatches[1]
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches persisted, got %d", len(matches))
	}

	// Verify both are exact matches with confidence 1.0
	for _, m := range matches {
		if m.MatchType != "exact" {
			t.Errorf("expected match type 'exact', got %q", m.MatchType)
		}
		if !m.Confidence.Valid || m.Confidence.Float64 != 1.0 {
			t.Errorf("expected confidence 1.0, got %v", m.Confidence)
		}
	}

	// Now AnalyzeRun should produce correct metrics
	metrics, err := svc.AnalyzeRun(ctx, 1)
	if err != nil {
		t.Fatalf("AnalyzeRun() error: %v", err)
	}

	if metrics.TP != 2 {
		t.Errorf("TP = %d, want 2", metrics.TP)
	}
	if metrics.FP != 1 {
		t.Errorf("FP = %d, want 1", metrics.FP)
	}
	if metrics.FN != 1 {
		t.Errorf("FN = %d, want 1", metrics.FN)
	}

	// Precision = TP/(TP+FP) = 2/3
	expectedPrecision := 2.0 / 3.0
	if math.Abs(metrics.Precision-expectedPrecision) > 0.001 {
		t.Errorf("Precision = %f, want %f", metrics.Precision, expectedPrecision)
	}

	// Recall = TP/(TP+FN) = 2/3
	expectedRecall := 2.0 / 3.0
	if math.Abs(metrics.Recall-expectedRecall) > 0.001 {
		t.Errorf("Recall = %f, want %f", metrics.Recall, expectedRecall)
	}
}

// TestCanaryMatchRunIdempotent verifies that MatchRun does not duplicate matches
// when called multiple times.
func TestCanaryMatchRunIdempotent(t *testing.T) {
	ms := newMockStore()

	ms.runs[1] = &store.Run{ID: 1, ProjectID: 100, Status: store.RunStatusCompleted}
	ms.findings[1] = []store.Finding{
		{ID: 10, RunID: 1, FilePath: "app.ts", StartLine: 10, CWEID: sql.NullString{String: "CWE-79", Valid: true}},
	}
	ms.annotations[1] = &store.Annotation{ID: 1, ProjectID: 100, FilePath: "app.ts", StartLine: 10, CWEID: sql.NullString{String: "CWE-79", Valid: true}, Status: store.AnnotationStatusValid}
	ms.unmatchedFindings[1] = nil
	ms.unmatchedAnnotations[1*1000+100] = nil

	svc := NewService(ms, nil)
	ctx := context.Background()

	// First call
	if err := svc.MatchRun(ctx, 1); err != nil {
		t.Fatalf("first MatchRun() error: %v", err)
	}
	if len(ms.findingMatches[1]) != 1 {
		t.Fatalf("expected 1 match after first call, got %d", len(ms.findingMatches[1]))
	}

	// Second call should be idempotent (matches already exist)
	if err := svc.MatchRun(ctx, 1); err != nil {
		t.Fatalf("second MatchRun() error: %v", err)
	}
	if len(ms.findingMatches[1]) != 1 {
		t.Errorf("expected 1 match after second call (idempotent), got %d", len(ms.findingMatches[1]))
	}
}
