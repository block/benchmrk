package report

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/store"
)

type mockStore struct {
	experiment *store.Experiment
	scanners   []store.Scanner
	projects   []store.CorpusProject
	runs       []store.Run
}

func (m *mockStore) GetExperiment(ctx context.Context, id int64) (*store.Experiment, error) {
	return m.experiment, nil
}

func (m *mockStore) ListExperimentScanners(ctx context.Context, experimentID int64) ([]store.Scanner, error) {
	return m.scanners, nil
}

func (m *mockStore) ListExperimentProjects(ctx context.Context, experimentID int64) ([]store.CorpusProject, error) {
	return m.projects, nil
}

func (m *mockStore) ListRunsByExperiment(ctx context.Context, experimentID int64) ([]store.Run, error) {
	return m.runs, nil
}

func (m *mockStore) GetScanner(ctx context.Context, id int64) (*store.Scanner, error) {
	for _, s := range m.scanners {
		if s.ID == id {
			return &s, nil
		}
	}
	return nil, nil
}

func (m *mockStore) GetProject(ctx context.Context, id int64) (*store.CorpusProject, error) {
	for _, p := range m.projects {
		if p.ID == id {
			return &p, nil
		}
	}
	return nil, nil
}

type mockAnalysis struct {
	metrics         map[int64]*analysis.Metrics
	categoryMetrics map[int64]map[string]*analysis.CategoryMetrics
}

func (m *mockAnalysis) AnalyzeRun(ctx context.Context, runID int64) (*analysis.Metrics, error) {
	if met, ok := m.metrics[runID]; ok {
		return met, nil
	}
	return &analysis.Metrics{}, nil
}

func (m *mockAnalysis) AnalyzeRunWithCategories(ctx context.Context, runID int64) (*analysis.Metrics, map[string]*analysis.CategoryMetrics, error) {
	met := &analysis.Metrics{}
	if m, ok := m.metrics[runID]; ok {
		met = m
	}
	cat := make(map[string]*analysis.CategoryMetrics)
	if c, ok := m.categoryMetrics[runID]; ok {
		cat = c
	}
	return met, cat, nil
}

func (m *mockAnalysis) AnalyzeRunDetail(ctx context.Context, runID int64) (*analysis.RunDetail, error) {
	met := &analysis.Metrics{}
	if mm, ok := m.metrics[runID]; ok {
		met = mm
	}
	cat := make(map[string]*analysis.CategoryMetrics)
	if c, ok := m.categoryMetrics[runID]; ok {
		cat = c
	}
	return &analysis.RunDetail{
		Metrics:           met,
		CategoryMetrics:   cat,
		AnnotationResults: []analysis.AnnotationResult{},
		FindingResults:    []analysis.FindingResult{},
	}, nil
}

func TestGenerateReportData(t *testing.T) {
	st := &mockStore{
		experiment: &store.Experiment{
			ID:          1,
			Name:        "Test Experiment",
			Description: sql.NullString{String: "Test description", Valid: true},
			Iterations:  3,
		},
		scanners: []store.Scanner{
			{ID: 1, Name: "ScannerA", Version: "1.0"},
			{ID: 2, Name: "ScannerB", Version: "2.0"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "Project1", Language: sql.NullString{String: "Go", Valid: true}},
			{ID: 2, Name: "Project2", Language: sql.NullString{String: "Python", Valid: true}},
		},
		runs: []store.Run{
			{ID: 1, ExperimentID: 1, ScannerID: 1, ProjectID: 1, Status: store.RunStatusCompleted},
			{ID: 2, ExperimentID: 1, ScannerID: 1, ProjectID: 2, Status: store.RunStatusCompleted},
			{ID: 3, ExperimentID: 1, ScannerID: 2, ProjectID: 1, Status: store.RunStatusCompleted},
			{ID: 4, ExperimentID: 1, ScannerID: 2, ProjectID: 2, Status: store.RunStatusCompleted},
		},
	}

	an := &mockAnalysis{
		metrics: map[int64]*analysis.Metrics{
			1: {TP: 10, FP: 2, FN: 3, Precision: 0.833, Recall: 0.769, F1: 0.8, DurationMs: 1000},
			2: {TP: 8, FP: 1, FN: 4, Precision: 0.889, Recall: 0.667, F1: 0.762, DurationMs: 1200},
			3: {TP: 12, FP: 3, FN: 2, Precision: 0.8, Recall: 0.857, F1: 0.828, DurationMs: 800},
			4: {TP: 9, FP: 2, FN: 3, Precision: 0.818, Recall: 0.75, F1: 0.783, DurationMs: 900},
		},
		categoryMetrics: map[int64]map[string]*analysis.CategoryMetrics{
			1: {"sql-injection": {TP: 5, FP: 1, FN: 1}, "xss": {TP: 5, FP: 1, FN: 2}},
			2: {"sql-injection": {TP: 4, FP: 0, FN: 2}, "xss": {TP: 4, FP: 1, FN: 2}},
			3: {"sql-injection": {TP: 6, FP: 1, FN: 1}, "xss": {TP: 6, FP: 2, FN: 1}},
			4: {"sql-injection": {TP: 5, FP: 1, FN: 2}, "xss": {TP: 4, FP: 1, FN: 1}},
		},
	}

	svc := NewService(st, an)
	data, err := svc.GenerateReportData(context.Background(), 1)
	if err != nil {
		t.Fatalf("GenerateReportData failed: %v", err)
	}

	if data.Experiment.Name != "Test Experiment" {
		t.Errorf("expected experiment name 'Test Experiment', got %q", data.Experiment.Name)
	}

	if len(data.Scanners) != 2 {
		t.Errorf("expected 2 scanners, got %d", len(data.Scanners))
	}

	if len(data.Projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(data.Projects))
	}

	if len(data.ByScanner) != 2 {
		t.Errorf("expected 2 scanner results, got %d", len(data.ByScanner))
	}

	if len(data.ByCategory) == 0 {
		t.Error("expected category data, got none")
	}

	if data.Summary.TotalRuns != 4 {
		t.Errorf("expected 4 total runs, got %d", data.Summary.TotalRuns)
	}
}

func TestFormatMarkdown(t *testing.T) {
	data := &ReportData{
		Title:       "Test Report",
		GeneratedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Experiment: ExperimentInfo{
			ID:          1,
			Name:        "Test Exp",
			Description: "A test experiment",
			Iterations:  3,
		},
		Scanners: []ScannerInfo{
			{ID: 1, Name: "Scanner1", Version: "1.0"},
		},
		Projects: []ProjectInfo{
			{ID: 1, Name: "Project1", Language: "Go"},
		},
		Summary: MetricsSummary{
			TotalRuns:     10,
			TotalFindings: 50,
			TotalTP:       40,
			TotalFP:       10,
			TotalFN:       5,
			AvgPrecision:  0.8,
			AvgRecall:     0.889,
			AvgF1:         0.842,
		},
		ByScanner: []ScannerResult{
			{
				ScannerName: "Scanner1",
				ScannerID:   1,
				RunCount:    10,
				Metrics: ScannerMetrics{
					TP:        40,
					FP:        10,
					FN:        5,
					Precision: 0.8,
					Recall:    0.889,
					F1:        0.842,
				},
				ByProject: []ProjectResult{
					{
						ProjectName: "Project1",
						ProjectID:   1,
						TP:          40,
						FP:          10,
						FN:          5,
						Precision:   0.8,
						Recall:      0.889,
						F1:          0.842,
						DurationMs:  1000,
					},
				},
			},
		},
		ByCategory: []CategoryStats{
			{Category: "sql-injection", TP: 20, FP: 5, FN: 3, Precision: 0.8, Recall: 0.87, F1: 0.833},
		},
	}

	var buf bytes.Buffer
	err := FormatMarkdown(data, &buf)
	if err != nil {
		t.Fatalf("FormatMarkdown failed: %v", err)
	}

	md := buf.String()

	if !strings.Contains(md, "# Test Report") {
		t.Error("markdown should contain title")
	}

	if !strings.Contains(md, "## Experiment") {
		t.Error("markdown should contain experiment section")
	}

	if !strings.Contains(md, "## Summary") {
		t.Error("markdown should contain summary section")
	}

	if !strings.Contains(md, "## Scanner Results") {
		t.Error("markdown should contain scanner results section")
	}

	if !strings.Contains(md, "## Category Breakdown") {
		t.Error("markdown should contain category breakdown section")
	}

	if !strings.Contains(md, "| Scanner |") {
		t.Error("markdown should contain scanner table")
	}

	if !strings.Contains(md, "| sql-injection |") {
		t.Error("markdown should contain category table row")
	}

	if !strings.Contains(md, "80.00%") {
		t.Error("markdown should format percentages correctly")
	}
}

func TestFormatMarkdownIncludesAllSections(t *testing.T) {
	data := &ReportData{
		Title:       "Full Report",
		GeneratedAt: time.Now(),
		Experiment:  ExperimentInfo{Name: "Exp", Iterations: 1},
		Scanners:    []ScannerInfo{{ID: 1, Name: "S1"}},
		Projects:    []ProjectInfo{{ID: 1, Name: "P1"}},
		Summary:     MetricsSummary{TotalRuns: 1},
		ByScanner: []ScannerResult{
			{ScannerName: "S1", RunCount: 1, Metrics: ScannerMetrics{Precision: 0.5}},
		},
		ByCategory: []CategoryStats{
			{Category: "xss", TP: 1},
		},
		Comparison: &ComparisonData{
			BaselineIndex: 0,
			Entries: []ComparisonEntry{
				{Scanner: ScannerInfo{Name: "A"}, Metrics: ComparisonMetrics{Precision: 0.7}},
				{Scanner: ScannerInfo{Name: "B"}, Metrics: ComparisonMetrics{Precision: 0.8}, Delta: &MetricDeltas{Precision: 0.1}},
			},
		},
	}

	var buf bytes.Buffer
	err := FormatMarkdown(data, &buf)
	if err != nil {
		t.Fatalf("FormatMarkdown failed: %v", err)
	}

	md := buf.String()

	sections := []string{
		"## Experiment",
		"## Summary",
		"## Scanner Results",
		"## Category Breakdown",
		"## Scanner Comparison",
	}

	for _, section := range sections {
		if !strings.Contains(md, section) {
			t.Errorf("markdown missing section: %s", section)
		}
	}
}

func TestFormatJSON(t *testing.T) {
	data := &ReportData{
		Title:       "JSON Test Report",
		GeneratedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Experiment: ExperimentInfo{
			ID:         1,
			Name:       "Test",
			Iterations: 1,
		},
		Summary: MetricsSummary{
			TotalRuns:    5,
			AvgPrecision: 0.85,
		},
	}

	var buf bytes.Buffer
	err := FormatJSON(data, &buf)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Error("FormatJSON should produce valid JSON")
	}

	if !strings.Contains(buf.String(), `"title"`) {
		t.Error("JSON should contain title field")
	}
}

func TestFormatJSONRoundTrip(t *testing.T) {
	original := &ReportData{
		Title:       "Round Trip Test",
		GeneratedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Experiment: ExperimentInfo{
			ID:          42,
			Name:        "My Experiment",
			Description: "Testing round trip",
			Iterations:  5,
		},
		Scanners: []ScannerInfo{
			{ID: 1, Name: "Scanner1", Version: "1.0.0"},
			{ID: 2, Name: "Scanner2", Version: "2.0.0"},
		},
		Projects: []ProjectInfo{
			{ID: 10, Name: "ProjectA", Language: "Go"},
		},
		Summary: MetricsSummary{
			TotalRuns:     10,
			TotalFindings: 100,
			TotalTP:       80,
			TotalFP:       15,
			TotalFN:       5,
			AvgPrecision:  0.842,
			AvgRecall:     0.941,
			AvgF1:         0.889,
		},
		ByScanner: []ScannerResult{
			{
				ScannerName: "Scanner1",
				ScannerID:   1,
				RunCount:    5,
				Metrics: ScannerMetrics{
					TP:        40,
					FP:        8,
					FN:        2,
					Precision: 0.833,
					Recall:    0.952,
					F1:        0.889,
				},
			},
		},
		ByCategory: []CategoryStats{
			{Category: "sql-injection", TP: 30, FP: 5, FN: 2, Precision: 0.857, Recall: 0.938, F1: 0.896},
		},
	}

	var buf bytes.Buffer
	if err := FormatJSON(original, &buf); err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	var decoded ReportData
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Title != original.Title {
		t.Errorf("title mismatch: got %q, want %q", decoded.Title, original.Title)
	}

	if decoded.Experiment.ID != original.Experiment.ID {
		t.Errorf("experiment ID mismatch: got %d, want %d", decoded.Experiment.ID, original.Experiment.ID)
	}

	if decoded.Experiment.Name != original.Experiment.Name {
		t.Errorf("experiment name mismatch: got %q, want %q", decoded.Experiment.Name, original.Experiment.Name)
	}

	if len(decoded.Scanners) != len(original.Scanners) {
		t.Errorf("scanners length mismatch: got %d, want %d", len(decoded.Scanners), len(original.Scanners))
	}

	if decoded.Summary.AvgPrecision != original.Summary.AvgPrecision {
		t.Errorf("avg precision mismatch: got %f, want %f", decoded.Summary.AvgPrecision, original.Summary.AvgPrecision)
	}

	if len(decoded.ByCategory) != len(original.ByCategory) {
		t.Errorf("categories length mismatch: got %d, want %d", len(decoded.ByCategory), len(original.ByCategory))
	}
}

func TestFormatMarkdownEmptyReport(t *testing.T) {
	data := &ReportData{
		Title:       "Empty Report",
		GeneratedAt: time.Now(),
		Experiment:  ExperimentInfo{Name: "Empty", Iterations: 1},
		Scanners:    []ScannerInfo{},
		Projects:    []ProjectInfo{},
		Summary:     MetricsSummary{},
		ByScanner:   []ScannerResult{},
		ByCategory:  []CategoryStats{},
	}

	var buf bytes.Buffer
	err := FormatMarkdown(data, &buf)
	if err != nil {
		t.Fatalf("FormatMarkdown failed on empty report: %v", err)
	}

	md := buf.String()

	if !strings.Contains(md, "# Empty Report") {
		t.Error("empty report should still have title")
	}

	if !strings.Contains(md, "*No scanner results available.*") {
		t.Error("empty report should indicate no scanner results")
	}

	if !strings.Contains(md, "*No category data available.*") {
		t.Error("empty report should indicate no category data")
	}
}

func TestFormatJSONEmptyReport(t *testing.T) {
	data := &ReportData{
		Title:       "Empty JSON Report",
		GeneratedAt: time.Now(),
		Experiment:  ExperimentInfo{Name: "Empty"},
	}

	var buf bytes.Buffer
	err := FormatJSON(data, &buf)
	if err != nil {
		t.Fatalf("FormatJSON failed on empty report: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Error("empty report should still produce valid JSON")
	}
}

func TestGenerateReportDataSingleScannerSingleProject(t *testing.T) {
	st := &mockStore{
		experiment: &store.Experiment{
			ID:         1,
			Name:       "Single",
			Iterations: 1,
		},
		scanners: []store.Scanner{
			{ID: 1, Name: "OnlyScanner", Version: "1.0"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "OnlyProject"},
		},
		runs: []store.Run{
			{ID: 1, ExperimentID: 1, ScannerID: 1, ProjectID: 1, Status: store.RunStatusCompleted},
		},
	}

	an := &mockAnalysis{
		metrics: map[int64]*analysis.Metrics{
			1: {TP: 5, FP: 1, FN: 1, Precision: 0.833, Recall: 0.833, F1: 0.833},
		},
		categoryMetrics: map[int64]map[string]*analysis.CategoryMetrics{
			1: {"injection": {TP: 5, FP: 1, FN: 1}},
		},
	}

	svc := NewService(st, an)
	data, err := svc.GenerateReportData(context.Background(), 1)
	if err != nil {
		t.Fatalf("GenerateReportData failed: %v", err)
	}

	if len(data.Scanners) != 1 {
		t.Errorf("expected 1 scanner, got %d", len(data.Scanners))
	}

	if len(data.Projects) != 1 {
		t.Errorf("expected 1 project, got %d", len(data.Projects))
	}

	if len(data.ByScanner) != 1 {
		t.Errorf("expected 1 scanner result, got %d", len(data.ByScanner))
	}

	var buf bytes.Buffer
	if err := FormatMarkdown(data, &buf); err != nil {
		t.Fatalf("FormatMarkdown failed: %v", err)
	}

	if !strings.Contains(buf.String(), "OnlyScanner") {
		t.Error("markdown should contain scanner name")
	}
}

func TestGenerateReportDataZeroResults(t *testing.T) {
	st := &mockStore{
		experiment: &store.Experiment{
			ID:         1,
			Name:       "Zero Results",
			Iterations: 1,
		},
		scanners: []store.Scanner{},
		projects: []store.CorpusProject{},
		runs:     []store.Run{},
	}

	an := &mockAnalysis{
		metrics:         map[int64]*analysis.Metrics{},
		categoryMetrics: map[int64]map[string]*analysis.CategoryMetrics{},
	}

	svc := NewService(st, an)
	data, err := svc.GenerateReportData(context.Background(), 1)
	if err != nil {
		t.Fatalf("GenerateReportData failed: %v", err)
	}

	var mdBuf bytes.Buffer
	if err := FormatMarkdown(data, &mdBuf); err != nil {
		t.Fatalf("FormatMarkdown failed on zero results: %v", err)
	}

	var jsonBuf bytes.Buffer
	if err := FormatJSON(data, &jsonBuf); err != nil {
		t.Fatalf("FormatJSON failed on zero results: %v", err)
	}

	if !json.Valid(jsonBuf.Bytes()) {
		t.Error("zero results should still produce valid JSON")
	}
}

func TestFormatCSV(t *testing.T) {
	data := createTestReportData()

	var buf bytes.Buffer
	err := FormatCSV(data, &buf)
	if err != nil {
		t.Fatalf("FormatCSV failed: %v", err)
	}

	csv := buf.String()

	if !strings.Contains(csv, "Scanner,Project,TP,FP,FN,TN,Precision,Recall,F1,Accuracy,AvgDuration,PeakMemory") {
		t.Error("CSV should contain headers")
	}

	if !strings.Contains(csv, "Scanner1") {
		t.Error("CSV should contain scanner name")
	}

	if !strings.Contains(csv, "Project1") {
		t.Error("CSV should contain project name")
	}

	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines (header + 1 data row), got %d", len(lines))
	}
}

func TestFormatCSVMultipleScannerProjects(t *testing.T) {
	data := &ReportData{
		Title:       "Multi CSV Test",
		GeneratedAt: time.Now(),
		ByScanner: []ScannerResult{
			{
				ScannerName: "ScannerA",
				ScannerID:   1,
				ByProject: []ProjectResult{
					{ProjectName: "Proj1", ProjectID: 1, TP: 10, FP: 2, FN: 1, Precision: 0.833, Recall: 0.909, F1: 0.87, DurationMs: 100, MemoryBytes: 1000},
					{ProjectName: "Proj2", ProjectID: 2, TP: 15, FP: 3, FN: 2, Precision: 0.833, Recall: 0.882, F1: 0.857, DurationMs: 200, MemoryBytes: 2000},
				},
			},
			{
				ScannerName: "ScannerB",
				ScannerID:   2,
				ByProject: []ProjectResult{
					{ProjectName: "Proj1", ProjectID: 1, TP: 12, FP: 1, FN: 3, Precision: 0.923, Recall: 0.8, F1: 0.857, DurationMs: 150, MemoryBytes: 1500},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := FormatCSV(data, &buf)
	if err != nil {
		t.Fatalf("FormatCSV failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Errorf("expected 4 lines (header + 3 data rows), got %d", len(lines))
	}
}

func TestFormatCSVSpecialCharacters(t *testing.T) {
	data := &ReportData{
		Title:       "Special Chars Test",
		GeneratedAt: time.Now(),
		ByScanner: []ScannerResult{
			{
				ScannerName: "Scanner, with comma",
				ScannerID:   1,
				ByProject: []ProjectResult{
					{ProjectName: "Project \"quoted\"", ProjectID: 1, TP: 5, FP: 1, FN: 0, Precision: 0.833, Recall: 1.0, F1: 0.909, DurationMs: 100, MemoryBytes: 1000},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := FormatCSV(data, &buf)
	if err != nil {
		t.Fatalf("FormatCSV failed: %v", err)
	}

	csv := buf.String()

	if !strings.Contains(csv, `"Scanner, with comma"`) {
		t.Error("CSV should properly escape commas in values")
	}

	if !strings.Contains(csv, `"Project ""quoted"""`) {
		t.Error("CSV should properly escape quotes in values")
	}
}

func TestFormatHTML(t *testing.T) {
	data := createTestReportData()

	var buf bytes.Buffer
	err := FormatHTML(data, &buf)
	if err != nil {
		t.Fatalf("FormatHTML failed: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "<html") {
		t.Error("HTML should contain <html> tag")
	}

	if !strings.Contains(html, "<body>") {
		t.Error("HTML should contain <body> tag")
	}

	if !strings.Contains(html, "<table>") {
		t.Error("HTML should contain <table> tag")
	}

	if !strings.Contains(html, "<style>") {
		t.Error("HTML should contain embedded <style> tag")
	}

	if strings.Contains(html, `rel="stylesheet"`) || strings.Contains(html, `href="http`) {
		t.Error("HTML should not contain external stylesheet links")
	}

	if !strings.Contains(html, "Test Report") {
		t.Error("HTML should contain report title")
	}

	if !strings.Contains(html, "Scanner1") {
		t.Error("HTML should contain scanner name")
	}
}

func TestFormatHTMLEmptyReport(t *testing.T) {
	data := &ReportData{
		Title:       "Empty HTML Report",
		GeneratedAt: time.Now(),
		Experiment:  ExperimentInfo{Name: "Empty", Iterations: 1},
		Scanners:    []ScannerInfo{},
		Projects:    []ProjectInfo{},
		Summary:     MetricsSummary{},
		ByScanner:   []ScannerResult{},
		ByCategory:  []CategoryStats{},
	}

	var buf bytes.Buffer
	err := FormatHTML(data, &buf)
	if err != nil {
		t.Fatalf("FormatHTML failed on empty report: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "<html") {
		t.Error("empty HTML should still have <html> tag")
	}

	if !strings.Contains(html, "No scanner results available") {
		t.Error("empty HTML should indicate no scanner results")
	}

	if !strings.Contains(html, "No category data available") {
		t.Error("empty HTML should indicate no category data")
	}
}

func TestFormatHTMLWithComparison(t *testing.T) {
	data := createTestReportData()
	data.Comparison = &ComparisonData{
		BaselineIndex: 0,
		Entries: []ComparisonEntry{
			{Scanner: ScannerInfo{ID: 1, Name: "ScannerA", Version: "1.0"}, Metrics: ComparisonMetrics{Precision: 0.8, Recall: 0.9, F1: 0.85, DurationMs: 100}},
			{Scanner: ScannerInfo{ID: 2, Name: "ScannerB", Version: "2.0"}, Metrics: ComparisonMetrics{Precision: 0.85, Recall: 0.88, F1: 0.865, DurationMs: 120}, Delta: &MetricDeltas{Precision: 0.05, Recall: -0.02, F1: 0.015, DurationMs: 20}},
		},
	}

	var buf bytes.Buffer
	err := FormatHTML(data, &buf)
	if err != nil {
		t.Fatalf("FormatHTML failed with comparison: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "Scanner Comparison") {
		t.Error("HTML should contain comparison section")
	}

	if !strings.Contains(html, "ScannerA") && !strings.Contains(html, "ScannerB") {
		t.Error("HTML should contain both scanner names in comparison")
	}
}

func TestFormatMarkdownThreeScannerComparison(t *testing.T) {
	delta1 := 0.05
	delta2 := -0.03
	data := createTestReportData()
	data.Comparison = &ComparisonData{
		BaselineIndex: 0,
		Entries: []ComparisonEntry{
			{Scanner: ScannerInfo{Name: "semgrep"}, Metrics: ComparisonMetrics{Precision: 0.8, Recall: 0.9, F1: 0.85, Accuracy: 0.88, DurationMs: 100}},
			{Scanner: ScannerInfo{Name: "codeql"}, Metrics: ComparisonMetrics{Precision: 0.85, Recall: 0.88, F1: 0.865, Accuracy: 0.9, DurationMs: 120}, Delta: &MetricDeltas{Precision: 0.05, Recall: -0.02, F1: 0.015, Accuracy: 0.02, DurationMs: 20}},
			{Scanner: ScannerInfo{Name: "repointerrogate"}, Metrics: ComparisonMetrics{Precision: 0.75, Recall: 0.92, F1: 0.83, Accuracy: 0.86, DurationMs: 80}, Delta: &MetricDeltas{Precision: -0.05, Recall: 0.02, F1: -0.02, Accuracy: -0.02, DurationMs: -20}},
		},
		ByProject: []ProjectComparisonN{
			{
				ProjectName: "juice-shop",
				ProjectID:   1,
				Entries: []ProjectComparisonEntry{
					{ScannerName: "semgrep", F1: 0.85},
					{ScannerName: "codeql", F1: 0.90, DeltaF1: &delta1},
					{ScannerName: "repointerrogate", F1: 0.82, DeltaF1: &delta2},
				},
			},
		},
	}

	// Test markdown
	var mdBuf bytes.Buffer
	if err := FormatMarkdown(data, &mdBuf); err != nil {
		t.Fatalf("FormatMarkdown failed: %v", err)
	}
	md := mdBuf.String()

	if !strings.Contains(md, "Comparing 3 scanners (baseline: semgrep)") {
		t.Error("markdown should show 3-scanner comparison header")
	}
	for _, name := range []string{"semgrep", "codeql", "repointerrogate"} {
		if !strings.Contains(md, name) {
			t.Errorf("markdown should contain scanner name %q", name)
		}
	}
	if !strings.Contains(md, "(+5.00%)") {
		t.Error("markdown should contain positive delta for codeql precision")
	}
	if !strings.Contains(md, "(-5.00%)") {
		t.Error("markdown should contain negative delta for repointerrogate precision")
	}
	if !strings.Contains(md, "### Per-Project Comparison") {
		t.Error("markdown should contain per-project comparison")
	}
	if !strings.Contains(md, "juice-shop") {
		t.Error("markdown should contain project name")
	}

	// Test HTML
	var htmlBuf bytes.Buffer
	if err := FormatHTML(data, &htmlBuf); err != nil {
		t.Fatalf("FormatHTML failed: %v", err)
	}
	html := htmlBuf.String()

	if !strings.Contains(html, "Scanner Comparison") {
		t.Error("HTML should contain comparison section")
	}
	if !strings.Contains(html, "3 scanners") {
		t.Error("HTML should show 3 scanners in comparison")
	}
	for _, name := range []string{"semgrep", "codeql", "repointerrogate"} {
		if !strings.Contains(html, name) {
			t.Errorf("HTML should contain scanner name %q", name)
		}
	}
	if !strings.Contains(html, "juice-shop") {
		t.Error("HTML should contain project name in per-project comparison")
	}
}

func TestFormatSARIF(t *testing.T) {
	data := createTestReportData()

	var buf bytes.Buffer
	err := FormatSARIF(data, &buf)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Error("FormatSARIF should produce valid JSON")
	}

	sarif := buf.String()

	if !strings.Contains(sarif, `"version": "2.1.0"`) {
		t.Error("SARIF should have version 2.1.0")
	}

	if !strings.Contains(sarif, `"$schema"`) {
		t.Error("SARIF should contain $schema field")
	}

	if !strings.Contains(sarif, `"runs"`) {
		t.Error("SARIF should contain runs array")
	}

	if !strings.Contains(sarif, `"tool"`) {
		t.Error("SARIF should contain tool information")
	}
}

func TestFormatSARIFEmpty(t *testing.T) {
	data := &ReportData{
		Title:       "Empty SARIF Report",
		GeneratedAt: time.Now(),
		Experiment:  ExperimentInfo{Name: "Empty"},
		ByScanner:   []ScannerResult{},
	}

	var buf bytes.Buffer
	err := FormatSARIF(data, &buf)
	if err != nil {
		t.Fatalf("FormatSARIF failed on empty report: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Error("empty SARIF should still produce valid JSON")
	}

	sarif := buf.String()

	if !strings.Contains(sarif, `"version": "2.1.0"`) {
		t.Error("empty SARIF should have version 2.1.0")
	}

	if !strings.Contains(sarif, `"runs"`) {
		t.Error("empty SARIF should have runs array")
	}
}

func TestFormatSARIFIncludesAllFindings(t *testing.T) {
	data := &ReportData{
		Title:       "SARIF Findings Test",
		GeneratedAt: time.Now(),
		Scanners: []ScannerInfo{
			{ID: 1, Name: "TestScanner", Version: "1.0.0"},
		},
		ByScanner: []ScannerResult{
			{
				ScannerName: "TestScanner",
				ScannerID:   1,
				ByProject: []ProjectResult{
					{ProjectName: "ProjectA", ProjectID: 1, TP: 10, FP: 2, FN: 1},
					{ProjectName: "ProjectB", ProjectID: 2, TP: 5, FP: 1, FN: 0},
				},
			},
		},
		ByCategory: []CategoryStats{
			{Category: "sql-injection", TP: 8, FP: 1, FN: 1},
			{Category: "xss", TP: 7, FP: 2, FN: 0},
		},
	}

	var buf bytes.Buffer
	err := FormatSARIF(data, &buf)
	if err != nil {
		t.Fatalf("FormatSARIF failed: %v", err)
	}

	sarif := buf.String()

	if !strings.Contains(sarif, "ProjectA") {
		t.Error("SARIF should contain ProjectA finding")
	}

	if !strings.Contains(sarif, "ProjectB") {
		t.Error("SARIF should contain ProjectB finding")
	}

	if !strings.Contains(sarif, "TestScanner") {
		t.Error("SARIF should contain scanner name in tool info")
	}

	if !strings.Contains(sarif, `"1.0.0"`) {
		t.Error("SARIF should contain scanner version")
	}
}

func TestFormatCSVEmptyReport(t *testing.T) {
	data := &ReportData{
		Title:       "Empty CSV Report",
		GeneratedAt: time.Now(),
		ByScanner:   []ScannerResult{},
	}

	var buf bytes.Buffer
	err := FormatCSV(data, &buf)
	if err != nil {
		t.Fatalf("FormatCSV failed on empty report: %v", err)
	}

	csv := buf.String()

	if !strings.Contains(csv, "Scanner,Project") {
		t.Error("empty CSV should still have headers")
	}

	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line (headers only), got %d", len(lines))
	}
}

func createTestReportData() *ReportData {
	return &ReportData{
		Title:       "Test Report",
		GeneratedAt: time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Experiment: ExperimentInfo{
			ID:          1,
			Name:        "Test Exp",
			Description: "A test experiment",
			Iterations:  3,
		},
		Scanners: []ScannerInfo{
			{ID: 1, Name: "Scanner1", Version: "1.0"},
		},
		Projects: []ProjectInfo{
			{ID: 1, Name: "Project1", Language: "Go"},
		},
		Summary: MetricsSummary{
			TotalRuns:     10,
			TotalFindings: 50,
			TotalTP:       40,
			TotalFP:       10,
			TotalFN:       5,
			AvgPrecision:  0.8,
			AvgRecall:     0.889,
			AvgF1:         0.842,
		},
		ByScanner: []ScannerResult{
			{
				ScannerName: "Scanner1",
				ScannerID:   1,
				RunCount:    10,
				Metrics: ScannerMetrics{
					TP:        40,
					FP:        10,
					FN:        5,
					Precision: 0.8,
					Recall:    0.889,
					F1:        0.842,
				},
				ByProject: []ProjectResult{
					{
						ProjectName: "Project1",
						ProjectID:   1,
						TP:          40,
						FP:          10,
						FN:          5,
						Precision:   0.8,
						Recall:      0.889,
						F1:          0.842,
						DurationMs:  1000,
						MemoryBytes: 50000,
					},
				},
			},
		},
		ByCategory: []CategoryStats{
			{Category: "sql-injection", TP: 20, FP: 5, FN: 3, Precision: 0.8, Recall: 0.87, F1: 0.833},
		},
	}
}
