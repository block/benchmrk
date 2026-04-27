package report

import (
	"context"
	"fmt"
	"time"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/store"
)

// Store defines the store methods needed by the report service.
type Store interface {
	GetExperiment(ctx context.Context, id int64) (*store.Experiment, error)
	ListExperimentScanners(ctx context.Context, experimentID int64) ([]store.Scanner, error)
	ListExperimentProjects(ctx context.Context, experimentID int64) ([]store.CorpusProject, error)
	ListRunsByExperiment(ctx context.Context, experimentID int64) ([]store.Run, error)
	GetScanner(ctx context.Context, id int64) (*store.Scanner, error)
	GetProject(ctx context.Context, id int64) (*store.CorpusProject, error)
}

// AnalysisService defines the analysis methods needed by the report service.
type AnalysisService interface {
	AnalyzeRun(ctx context.Context, runID int64) (*analysis.Metrics, error)
	AnalyzeRunWithCategories(ctx context.Context, runID int64) (*analysis.Metrics, map[string]*analysis.CategoryMetrics, error)
	AnalyzeRunDetail(ctx context.Context, runID int64) (*analysis.RunDetail, error)
}

// Service provides report generation functionality.
type Service struct {
	store    Store
	analysis AnalysisService
}

// NewService creates a report service with the given dependencies.
func NewService(s Store, a AnalysisService) *Service {
	return &Service{
		store:    s,
		analysis: a,
	}
}

// GenerateReportData assembles all data for a report from an experiment.
func (s *Service) GenerateReportData(ctx context.Context, experimentID int64) (*ReportData, error) {
	exp, err := s.store.GetExperiment(ctx, experimentID)
	if err != nil {
		return nil, fmt.Errorf("get experiment: %w", err)
	}

	scanners, err := s.store.ListExperimentScanners(ctx, experimentID)
	if err != nil {
		return nil, fmt.Errorf("list scanners: %w", err)
	}

	projects, err := s.store.ListExperimentProjects(ctx, experimentID)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}

	runs, err := s.store.ListRunsByExperiment(ctx, experimentID)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}

	report := &ReportData{
		Title:       fmt.Sprintf("Benchmark Report: %s", exp.Name),
		GeneratedAt: time.Now().UTC(),
		Experiment: ExperimentInfo{
			ID:         exp.ID,
			Name:       exp.Name,
			Iterations: exp.Iterations,
		},
	}
	if exp.Description.Valid {
		report.Experiment.Description = exp.Description.String
	}

	for _, sc := range scanners {
		report.Scanners = append(report.Scanners, ScannerInfo{
			ID:      sc.ID,
			Name:    sc.Name,
			Version: sc.Version,
		})
	}

	for _, p := range projects {
		pi := ProjectInfo{
			ID:   p.ID,
			Name: p.Name,
		}
		if p.Language.Valid {
			pi.Language = p.Language.String
		}
		report.Projects = append(report.Projects, pi)
	}

	scannerRuns := make(map[int64][]store.Run)
	for _, run := range runs {
		if run.Status == store.RunStatusCompleted {
			scannerRuns[run.ScannerID] = append(scannerRuns[run.ScannerID], run)
		}
	}

	categoryTotals := make(map[string]*CategoryStats)
	var totalTP, totalFP, totalFN, totalTN int
	var totalPrecision, totalRecall, totalF1, totalAccuracy float64
	var totalDuration, totalMemory float64
	var runCount int

	for _, sc := range scanners {
		scRuns := scannerRuns[sc.ID]
		sr := ScannerResult{
			ScannerName: sc.Name,
			ScannerID:   sc.ID,
			RunCount:    len(scRuns),
		}

		projectRuns := make(map[int64][]store.Run)
		for _, run := range scRuns {
			projectRuns[run.ProjectID] = append(projectRuns[run.ProjectID], run)
		}

		var scTP, scFP, scFN, scTN int
		var scPrecisions, scRecalls, scF1s []float64
		var scDurations, scMemories []float64

		for _, p := range projects {
			pRuns := projectRuns[p.ID]
			if len(pRuns) == 0 {
				continue
			}

			// Analyze all iterations and average metrics.
			allMetrics := make([]*analysis.Metrics, 0, len(pRuns))
			for _, r := range pRuns {
				m, err := s.analysis.AnalyzeRun(ctx, r.ID)
				if err != nil {
					return nil, fmt.Errorf("analyze run %d: %w", r.ID, err)
				}
				allMetrics = append(allMetrics, m)
			}
			metrics := analysis.AverageMetrics(allMetrics)

			// Use the median-F1 run for annotation/finding detail and category breakdown.
			medianIdx := analysis.MedianF1Index(allMetrics)
			representativeRun := pRuns[medianIdx]
			detail, err := s.analysis.AnalyzeRunDetail(ctx, representativeRun.ID)
			if err != nil {
				return nil, fmt.Errorf("analyze run %d: %w", representativeRun.ID, err)
			}
			catMetrics := detail.CategoryMetrics

			pr := ProjectResult{
				ProjectName: p.Name,
				ProjectID:   p.ID,
				TP:          metrics.TP,
				FP:          metrics.FP,
				FN:          metrics.FN,
				TN:          metrics.TN,
				Precision:   metrics.Precision,
				Recall:      metrics.Recall,
				F1:          metrics.F1,
				Accuracy:    metrics.Accuracy,
				DurationMs:  metrics.DurationMs,
				MemoryBytes: metrics.MemoryPeakBytes,
			}

			// Populate annotation coverage detail
			for _, ar := range detail.AnnotationResults {
				ac := AnnotationCoverage{
					ID:             ar.Annotation.ID,
					FilePath:       ar.Annotation.FilePath,
					StartLine:      ar.Annotation.StartLine,
					Category:       ar.Annotation.Category,
					Severity:       ar.Annotation.Severity,
					Status:         string(ar.Annotation.Status),
					Matched:        ar.Matched,
					MatchType:      ar.MatchType,
					Confidence:     ar.Confidence,
					Classification: ar.Classification,
				}
				if ar.Annotation.EndLine.Valid {
					ac.EndLine = int(ar.Annotation.EndLine.Int64)
				}
				if ar.Annotation.CWEID.Valid {
					ac.CWEID = ar.Annotation.CWEID.String
				}
				if ar.Annotation.Description.Valid {
					ac.Description = ar.Annotation.Description.String
				}
				pr.Annotations = append(pr.Annotations, ac)
			}

			// Populate unmatched findings
			for _, fr := range detail.FindingResults {
				if !fr.Matched {
					uf := UnmatchedFinding{
						FilePath:  fr.Finding.FilePath,
						StartLine: fr.Finding.StartLine,
					}
					if fr.Finding.CWEID.Valid {
						uf.CWEID = fr.Finding.CWEID.String
					}
					if fr.Finding.RuleID.Valid {
						uf.RuleID = fr.Finding.RuleID.String
					}
					if fr.Finding.Severity.Valid {
						uf.Severity = fr.Finding.Severity.String
					}
					if fr.Finding.Message.Valid {
						uf.Message = fr.Finding.Message.String
					}
					pr.UnmatchedFindings = append(pr.UnmatchedFindings, uf)
				}
			}

			sr.ByProject = append(sr.ByProject, pr)

			scTP += metrics.TP
			scFP += metrics.FP
			scFN += metrics.FN
			scTN += metrics.TN
			scPrecisions = append(scPrecisions, metrics.Precision)
			scRecalls = append(scRecalls, metrics.Recall)
			scF1s = append(scF1s, metrics.F1)
			scDurations = append(scDurations, float64(metrics.DurationMs))
			scMemories = append(scMemories, float64(metrics.MemoryPeakBytes))

			for cat, cm := range catMetrics {
				if categoryTotals[cat] == nil {
					categoryTotals[cat] = &CategoryStats{Category: cat}
				}
				categoryTotals[cat].TP += cm.TP
				categoryTotals[cat].FP += cm.FP
				categoryTotals[cat].FN += cm.FN
				categoryTotals[cat].TN += cm.TN
			}
		}

		sr.Metrics = ScannerMetrics{
			TP:        scTP,
			FP:        scFP,
			FN:        scFN,
			TN:        scTN,
			Precision: safeDivide(float64(scTP), float64(scTP+scFP)),
			Recall:    safeDivide(float64(scTP), float64(scTP+scFN)),
		}
		sr.Metrics.F1 = safeF1(sr.Metrics.Precision, sr.Metrics.Recall)
		sr.Metrics.Accuracy = safeDivide(float64(scTP+scTN), float64(scTP+scTN+scFP+scFN))

		if len(scPrecisions) > 0 {
			sr.Metrics.PrecisionStdDev = stdDev(scPrecisions)
			sr.Metrics.RecallStdDev = stdDev(scRecalls)
			sr.Metrics.F1StdDev = stdDev(scF1s)
			sr.Metrics.DurationMean = mean(scDurations)
			sr.Metrics.MemoryMean = mean(scMemories)
		}

		report.ByScanner = append(report.ByScanner, sr)

		totalTP += scTP
		totalFP += scFP
		totalFN += scFN
		totalTN += scTN
		totalPrecision += sr.Metrics.Precision
		totalRecall += sr.Metrics.Recall
		totalF1 += sr.Metrics.F1
		totalAccuracy += sr.Metrics.Accuracy
		totalDuration += sr.Metrics.DurationMean
		totalMemory += sr.Metrics.MemoryMean
		runCount += sr.RunCount
	}

	scannerCount := len(scanners)
	if scannerCount > 0 {
		report.Summary = MetricsSummary{
			TotalRuns:      runCount,
			TotalFindings:  totalTP + totalFP,
			TotalTP:        totalTP,
			TotalFP:        totalFP,
			TotalFN:        totalFN,
			TotalTN:        totalTN,
			AvgPrecision:   totalPrecision / float64(scannerCount),
			AvgRecall:      totalRecall / float64(scannerCount),
			AvgF1:          totalF1 / float64(scannerCount),
			AvgAccuracy:    totalAccuracy / float64(scannerCount),
			AvgDurationMs:  totalDuration / float64(scannerCount),
			AvgMemoryBytes: totalMemory / float64(scannerCount),
		}
	}

	for _, cs := range categoryTotals {
		cs.Precision = safeDivide(float64(cs.TP), float64(cs.TP+cs.FP))
		cs.Recall = safeDivide(float64(cs.TP), float64(cs.TP+cs.FN))
		cs.F1 = safeF1(cs.Precision, cs.Recall)
		cs.Accuracy = safeDivide(float64(cs.TP+cs.TN), float64(cs.TP+cs.TN+cs.FP+cs.FN))
		report.ByCategory = append(report.ByCategory, *cs)
	}

	return report, nil
}

func safeDivide(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func safeF1(precision, recall float64) float64 {
	sum := precision + recall
	if sum == 0 {
		return 0
	}
	return 2 * precision * recall / sum
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stdDev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := mean(values)
	var sumSquares float64
	for _, v := range values {
		diff := v - m
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(values))
	if variance < 0 {
		return 0
	}
	return sqrt(variance)
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z -= (z*z - x) / (2 * z)
	}
	return z
}
