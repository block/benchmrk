package report

import "time"

// ReportData contains all data needed to generate a benchmark report.
type ReportData struct {
	Title       string          `json:"title"`
	GeneratedAt time.Time       `json:"generated_at"`
	Experiment  ExperimentInfo  `json:"experiment"`
	Scanners    []ScannerInfo   `json:"scanners"`
	Projects    []ProjectInfo   `json:"projects"`
	Summary     MetricsSummary  `json:"summary"`
	ByScanner   []ScannerResult `json:"by_scanner"`
	ByCategory  []CategoryStats `json:"by_category"`
	Comparison  *ComparisonData `json:"comparison,omitempty"`
}

// ExperimentInfo contains experiment metadata.
type ExperimentInfo struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Iterations  int    `json:"iterations"`
}

// ScannerInfo contains scanner metadata.
type ScannerInfo struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ProjectInfo contains project metadata.
type ProjectInfo struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Language string `json:"language,omitempty"`
}

// MetricsSummary contains aggregate metrics across all scanners/projects.
type MetricsSummary struct {
	TotalRuns      int     `json:"total_runs"`
	TotalFindings  int     `json:"total_findings"`
	TotalTP        int     `json:"total_tp"`
	TotalFP        int     `json:"total_fp"`
	TotalFN        int     `json:"total_fn"`
	TotalTN        int     `json:"total_tn"`
	AvgPrecision   float64 `json:"avg_precision"`
	AvgRecall      float64 `json:"avg_recall"`
	AvgF1          float64 `json:"avg_f1"`
	AvgAccuracy    float64 `json:"avg_accuracy"`
	AvgDurationMs  float64 `json:"avg_duration_ms"`
	AvgMemoryBytes float64 `json:"avg_memory_bytes"`
}

// ScannerResult contains per-scanner results with metrics.
type ScannerResult struct {
	ScannerName string          `json:"scanner_name"`
	ScannerID   int64           `json:"scanner_id"`
	RunCount    int             `json:"run_count"`
	Metrics     ScannerMetrics  `json:"metrics"`
	ByProject   []ProjectResult `json:"by_project"`
}

// ScannerMetrics contains aggregated metrics for a scanner.
type ScannerMetrics struct {
	TP              int     `json:"tp"`
	FP              int     `json:"fp"`
	FN              int     `json:"fn"`
	TN              int     `json:"tn"`
	Precision       float64 `json:"precision"`
	Recall          float64 `json:"recall"`
	F1              float64 `json:"f1"`
	Accuracy        float64 `json:"accuracy"`
	PrecisionStdDev float64 `json:"precision_stddev,omitempty"`
	RecallStdDev    float64 `json:"recall_stddev,omitempty"`
	F1StdDev        float64 `json:"f1_stddev,omitempty"`
	DurationMean    float64 `json:"duration_mean_ms,omitempty"`
	MemoryMean      float64 `json:"memory_mean_bytes,omitempty"`
}

// ProjectResult contains per-project results for a scanner.
type ProjectResult struct {
	ProjectName       string               `json:"project_name"`
	ProjectID         int64                `json:"project_id"`
	TP                int                  `json:"tp"`
	FP                int                  `json:"fp"`
	FN                int                  `json:"fn"`
	TN                int                  `json:"tn"`
	Precision         float64              `json:"precision"`
	Recall            float64              `json:"recall"`
	F1                float64              `json:"f1"`
	Accuracy          float64              `json:"accuracy"`
	DurationMs        int64                `json:"duration_ms"`
	MemoryBytes       int64                `json:"memory_bytes"`
	Annotations       []AnnotationCoverage `json:"annotations,omitempty"`
	UnmatchedFindings []UnmatchedFinding   `json:"unmatched_findings,omitempty"`
}

// CategoryStats contains per-category metrics breakdown.
type CategoryStats struct {
	Category  string  `json:"category"`
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	TN        int     `json:"tn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Accuracy  float64 `json:"accuracy"`
}

// ComparisonData contains side-by-side scanner comparison for N scanners.
type ComparisonData struct {
	BaselineIndex int                  `json:"baseline_index,omitempty"`
	Entries       []ComparisonEntry    `json:"entries"`
	ByProject     []ProjectComparisonN `json:"by_project,omitempty"`
}

// ComparisonEntry holds one scanner's comparison data.
type ComparisonEntry struct {
	Scanner ScannerInfo       `json:"scanner"`
	Metrics ComparisonMetrics `json:"metrics"`
	Delta   *MetricDeltas     `json:"delta,omitempty"` // nil for baseline scanner
}

// ComparisonMetrics contains metrics for comparison.
type ComparisonMetrics struct {
	Precision   float64 `json:"precision"`
	Recall      float64 `json:"recall"`
	F1          float64 `json:"f1"`
	Accuracy    float64 `json:"accuracy"`
	DurationMs  float64 `json:"duration_ms"`
	MemoryBytes float64 `json:"memory_bytes"`
}

// MetricDeltas contains deltas between a scanner and the baseline.
type MetricDeltas struct {
	Precision   float64 `json:"precision"`
	Recall      float64 `json:"recall"`
	F1          float64 `json:"f1"`
	Accuracy    float64 `json:"accuracy"`
	DurationMs  float64 `json:"duration_ms"`
	MemoryBytes float64 `json:"memory_bytes"`
}

// ProjectComparisonN contains per-project comparison data for N scanners.
type ProjectComparisonN struct {
	ProjectName string                   `json:"project_name"`
	ProjectID   int64                    `json:"project_id"`
	Entries     []ProjectComparisonEntry `json:"entries"`
}

// ProjectComparisonEntry holds one scanner's per-project comparison data.
type ProjectComparisonEntry struct {
	ScannerName string   `json:"scanner_name"`
	F1          float64  `json:"f1"`
	DeltaF1     *float64 `json:"delta_f1,omitempty"`
}

// AnnotationCoverage shows how each annotation was handled in a run.
type AnnotationCoverage struct {
	ID             int64   `json:"id"`
	FilePath       string  `json:"file_path"`
	StartLine      int     `json:"start_line"`
	EndLine        int     `json:"end_line,omitempty"`
	CWEID          string  `json:"cwe_id,omitempty"`
	Category       string  `json:"category"`
	Severity       string  `json:"severity"`
	Description    string  `json:"description,omitempty"`
	Status         string  `json:"status"`               // valid, invalid, disputed
	Matched        bool    `json:"matched"`              // was it triggered?
	MatchType      string  `json:"match_type,omitempty"` // exact, fuzzy, category
	Confidence     float64 `json:"confidence,omitempty"`
	Classification string  `json:"classification"` // TP, FP, TN, FN
}

// UnmatchedFinding shows a finding that didn't match any annotation.
type UnmatchedFinding struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	CWEID     string `json:"cwe_id,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Message   string `json:"message,omitempty"`
}
