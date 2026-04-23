package analysis

import (
	"database/sql"
	"math"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

func TestComputeMetricsWithKnownTPFPFN(t *testing.T) {
	// Setup: 3 TP, 2 FP (1 unmatched + 1 matched fp), 1 FN (unmatched tp annotation)
	matchesWithAnnotations := []MatchWithAnnotation{
		{Match: store.FindingMatch{FindingID: 1}, Annotation: store.Annotation{ID: 1, Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 2}, Annotation: store.Annotation{ID: 2, Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 3}, Annotation: store.Annotation{ID: 3, Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 4}, Annotation: store.Annotation{ID: 4, Status: store.AnnotationStatusInvalid}},
	}
	unmatchedFindings := []store.Finding{{ID: 5}}
	unmatchedAnnotations := []store.Annotation{{ID: 6, Status: store.AnnotationStatusValid}}

	m := ComputeMetrics(matchesWithAnnotations, unmatchedFindings, unmatchedAnnotations, nil)

	if m.TP != 3 {
		t.Errorf("TP = %d, want 3", m.TP)
	}
	if m.FP != 2 {
		t.Errorf("FP = %d, want 2", m.FP)
	}
	if m.FN != 1 {
		t.Errorf("FN = %d, want 1", m.FN)
	}

	// Precision = 3 / (3 + 2) = 0.6
	expectedPrecision := 0.6
	if math.Abs(m.Precision-expectedPrecision) > 0.001 {
		t.Errorf("Precision = %f, want %f", m.Precision, expectedPrecision)
	}

	// Recall = 3 / (3 + 1) = 0.75
	expectedRecall := 0.75
	if math.Abs(m.Recall-expectedRecall) > 0.001 {
		t.Errorf("Recall = %f, want %f", m.Recall, expectedRecall)
	}

	// F1 = 2 * (0.6 * 0.75) / (0.6 + 0.75) = 0.6666...
	expectedF1 := 2 * 0.6 * 0.75 / (0.6 + 0.75)
	if math.Abs(m.F1-expectedF1) > 0.001 {
		t.Errorf("F1 = %f, want %f", m.F1, expectedF1)
	}
}

func TestPrecisionOneWhenFPIsZero(t *testing.T) {
	matchesWithAnnotations := []MatchWithAnnotation{
		{Match: store.FindingMatch{FindingID: 1}, Annotation: store.Annotation{ID: 1, Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 2}, Annotation: store.Annotation{ID: 2, Status: store.AnnotationStatusValid}},
	}

	m := ComputeMetrics(matchesWithAnnotations, []store.Finding{}, []store.Annotation{}, nil)

	if m.TP != 2 {
		t.Errorf("TP = %d, want 2", m.TP)
	}
	if m.FP != 0 {
		t.Errorf("FP = %d, want 0", m.FP)
	}
	if m.Precision != 1.0 {
		t.Errorf("Precision = %f, want 1.0", m.Precision)
	}
}

func TestRecallOneWhenFNIsZero(t *testing.T) {
	matchesWithAnnotations := []MatchWithAnnotation{
		{Match: store.FindingMatch{FindingID: 1}, Annotation: store.Annotation{ID: 1, Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 2}, Annotation: store.Annotation{ID: 2, Status: store.AnnotationStatusValid}},
	}

	m := ComputeMetrics(matchesWithAnnotations, []store.Finding{}, []store.Annotation{}, nil)

	if m.TP != 2 {
		t.Errorf("TP = %d, want 2", m.TP)
	}
	if m.FN != 0 {
		t.Errorf("FN = %d, want 0", m.FN)
	}
	if m.Recall != 1.0 {
		t.Errorf("Recall = %f, want 1.0", m.Recall)
	}
}

func TestF1ZeroWhenPrecisionAndRecallZero(t *testing.T) {
	// No TP, only FP
	unmatchedFindings := []store.Finding{{ID: 1}, {ID: 2}}

	m := ComputeMetrics([]MatchWithAnnotation{}, unmatchedFindings, []store.Annotation{}, nil)

	if m.TP != 0 {
		t.Errorf("TP = %d, want 0", m.TP)
	}
	if m.Precision != 0 {
		t.Errorf("Precision = %f, want 0", m.Precision)
	}
	if m.F1 != 0 {
		t.Errorf("F1 = %f, want 0", m.F1)
	}
}

func TestDivisionByZeroReturnsZero(t *testing.T) {
	// No TP and no (TP + FP) → Precision division by zero
	m := ComputeMetrics([]MatchWithAnnotation{}, []store.Finding{}, []store.Annotation{}, nil)

	if math.IsNaN(m.Precision) || math.IsInf(m.Precision, 0) {
		t.Errorf("Precision is NaN or Inf, want 0")
	}
	if math.IsNaN(m.Recall) || math.IsInf(m.Recall, 0) {
		t.Errorf("Recall is NaN or Inf, want 0")
	}
	if math.IsNaN(m.F1) || math.IsInf(m.F1, 0) {
		t.Errorf("F1 is NaN or Inf, want 0")
	}
	if m.Precision != 0 {
		t.Errorf("Precision = %f, want 0", m.Precision)
	}
	if m.Recall != 0 {
		t.Errorf("Recall = %f, want 0", m.Recall)
	}
	if m.F1 != 0 {
		t.Errorf("F1 = %f, want 0", m.F1)
	}
}

func TestComputeCategoryMetricsGroupsCorrectly(t *testing.T) {
	matchesWithAnnotations := []MatchWithAnnotation{
		{Match: store.FindingMatch{FindingID: 1}, Annotation: store.Annotation{ID: 1, Category: "sql-injection", Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 2}, Annotation: store.Annotation{ID: 2, Category: "sql-injection", Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 3}, Annotation: store.Annotation{ID: 3, Category: "xss", Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 4}, Annotation: store.Annotation{ID: 4, Category: "xss", Status: store.AnnotationStatusInvalid}},
	}
	unmatchedFindings := []store.Finding{
		{ID: 5, CWEID: sql.NullString{String: "CWE-89", Valid: true}}, // sql-injection
	}
	unmatchedAnnotations := []store.Annotation{
		{ID: 6, Category: "xss", Status: store.AnnotationStatusValid},
	}

	cm := ComputeCategoryMetrics(matchesWithAnnotations, unmatchedFindings, unmatchedAnnotations, nil)

	// Check sql-injection: 2 TP, 1 FP (unmatched finding), 0 FN
	sqlInj, ok := cm["sql-injection"]
	if !ok {
		t.Fatal("Expected sql-injection category")
	}
	if sqlInj.TP != 2 {
		t.Errorf("sql-injection TP = %d, want 2", sqlInj.TP)
	}
	if sqlInj.FP != 1 {
		t.Errorf("sql-injection FP = %d, want 1", sqlInj.FP)
	}
	if sqlInj.FN != 0 {
		t.Errorf("sql-injection FN = %d, want 0", sqlInj.FN)
	}

	// Check xss: 1 TP, 1 matched FP, 1 FN
	xss, ok := cm["xss"]
	if !ok {
		t.Fatal("Expected xss category")
	}
	if xss.TP != 1 {
		t.Errorf("xss TP = %d, want 1", xss.TP)
	}
	if xss.FP != 1 {
		t.Errorf("xss FP = %d, want 1", xss.FP)
	}
	if xss.FN != 1 {
		t.Errorf("xss FN = %d, want 1", xss.FN)
	}
}

func TestAggregateRunMetricsComputesCorrectMean(t *testing.T) {
	runs := []RunMetrics{
		{Metrics: Metrics{Precision: 0.8, Recall: 0.6, F1: 0.69, DurationMs: 100, MemoryPeakBytes: 1000}},
		{Metrics: Metrics{Precision: 0.6, Recall: 0.8, F1: 0.69, DurationMs: 200, MemoryPeakBytes: 2000}},
		{Metrics: Metrics{Precision: 0.7, Recall: 0.7, F1: 0.70, DurationMs: 300, MemoryPeakBytes: 3000}},
	}

	agg := AggregateRunMetrics(runs)

	expectedPrecisionMean := (0.8 + 0.6 + 0.7) / 3
	if math.Abs(agg.PrecisionMean-expectedPrecisionMean) > 0.001 {
		t.Errorf("PrecisionMean = %f, want %f", agg.PrecisionMean, expectedPrecisionMean)
	}

	expectedDurationMean := (100.0 + 200.0 + 300.0) / 3
	if math.Abs(agg.DurationMean-expectedDurationMean) > 0.001 {
		t.Errorf("DurationMean = %f, want %f", agg.DurationMean, expectedDurationMean)
	}
}

func TestAggregateRunMetricsComputesCorrectMedianOdd(t *testing.T) {
	runs := []RunMetrics{
		{Metrics: Metrics{Precision: 0.5}},
		{Metrics: Metrics{Precision: 0.8}},
		{Metrics: Metrics{Precision: 0.6}},
	}

	agg := AggregateRunMetrics(runs)

	// Sorted: 0.5, 0.6, 0.8 → median = 0.6
	expectedMedian := 0.6
	if math.Abs(agg.PrecisionMedian-expectedMedian) > 0.001 {
		t.Errorf("PrecisionMedian = %f, want %f", agg.PrecisionMedian, expectedMedian)
	}
}

func TestAggregateRunMetricsComputesCorrectMedianEven(t *testing.T) {
	runs := []RunMetrics{
		{Metrics: Metrics{Precision: 0.4}},
		{Metrics: Metrics{Precision: 0.5}},
		{Metrics: Metrics{Precision: 0.7}},
		{Metrics: Metrics{Precision: 0.8}},
	}

	agg := AggregateRunMetrics(runs)

	// Sorted: 0.4, 0.5, 0.7, 0.8 → median = (0.5 + 0.7) / 2 = 0.6
	expectedMedian := 0.6
	if math.Abs(agg.PrecisionMedian-expectedMedian) > 0.001 {
		t.Errorf("PrecisionMedian = %f, want %f", agg.PrecisionMedian, expectedMedian)
	}
}

func TestAggregateRunMetricsComputesCorrectStdDev(t *testing.T) {
	runs := []RunMetrics{
		{Metrics: Metrics{Precision: 2.0}},
		{Metrics: Metrics{Precision: 4.0}},
		{Metrics: Metrics{Precision: 4.0}},
		{Metrics: Metrics{Precision: 4.0}},
		{Metrics: Metrics{Precision: 5.0}},
		{Metrics: Metrics{Precision: 5.0}},
		{Metrics: Metrics{Precision: 7.0}},
		{Metrics: Metrics{Precision: 9.0}},
	}

	agg := AggregateRunMetrics(runs)

	// Mean = 5, population stddev = 2
	expectedMean := 5.0
	expectedStdDev := 2.0
	if math.Abs(agg.PrecisionMean-expectedMean) > 0.001 {
		t.Errorf("PrecisionMean = %f, want %f", agg.PrecisionMean, expectedMean)
	}
	if math.Abs(agg.PrecisionStdDev-expectedStdDev) > 0.001 {
		t.Errorf("PrecisionStdDev = %f, want %f", agg.PrecisionStdDev, expectedStdDev)
	}
}

func TestNoFindingsAndNoAnnotationsReturnsAllZeros(t *testing.T) {
	m := ComputeMetrics([]MatchWithAnnotation{}, []store.Finding{}, []store.Annotation{}, nil)

	if m.TP != 0 {
		t.Errorf("TP = %d, want 0", m.TP)
	}
	if m.FP != 0 {
		t.Errorf("FP = %d, want 0", m.FP)
	}
	if m.FN != 0 {
		t.Errorf("FN = %d, want 0", m.FN)
	}
	if m.Precision != 0 {
		t.Errorf("Precision = %f, want 0", m.Precision)
	}
	if m.Recall != 0 {
		t.Errorf("Recall = %f, want 0", m.Recall)
	}
	if m.F1 != 0 {
		t.Errorf("F1 = %f, want 0", m.F1)
	}
}

func TestAllFindingsAreFalsePositives(t *testing.T) {
	// All unmatched findings → FP only, no TP
	unmatchedFindings := []store.Finding{{ID: 1}, {ID: 2}, {ID: 3}}

	m := ComputeMetrics([]MatchWithAnnotation{}, unmatchedFindings, []store.Annotation{}, nil)

	if m.TP != 0 {
		t.Errorf("TP = %d, want 0", m.TP)
	}
	if m.FP != 3 {
		t.Errorf("FP = %d, want 3", m.FP)
	}
	if m.Precision != 0 {
		t.Errorf("Precision = %f, want 0", m.Precision)
	}
	// Recall undefined (0/0), should be 0
	if m.Recall != 0 {
		t.Errorf("Recall = %f, want 0 (undefined, clamped to 0)", m.Recall)
	}
}

func TestAggregateRunMetricsEmptyReturnsZeros(t *testing.T) {
	agg := AggregateRunMetrics([]RunMetrics{})

	if agg.Count != 0 {
		t.Errorf("Count = %d, want 0", agg.Count)
	}
	if agg.PrecisionMean != 0 {
		t.Errorf("PrecisionMean = %f, want 0", agg.PrecisionMean)
	}
	if agg.PrecisionStdDev != 0 {
		t.Errorf("PrecisionStdDev = %f, want 0", agg.PrecisionStdDev)
	}
}

func TestUnmatchedAnnotationsClassifiedByStatus(t *testing.T) {
	// Unmatched "valid" → FN, unmatched "invalid" → TN, other statuses → ignored
	unmatchedAnnotations := []store.Annotation{
		{ID: 1, Status: store.AnnotationStatusValid},
		{ID: 2, Status: store.AnnotationStatusInvalid},
		{ID: 3, Status: store.AnnotationStatusDisputed},
	}

	m := ComputeMetrics([]MatchWithAnnotation{}, []store.Finding{}, unmatchedAnnotations, nil)

	if m.FN != 1 {
		t.Errorf("FN = %d, want 1 (only status='valid' counts as FN)", m.FN)
	}
	if m.TN != 1 {
		t.Errorf("TN = %d, want 1 (only status='invalid' counts as TN)", m.TN)
	}
}

func TestAccuracyComputation(t *testing.T) {
	// 2 TP, 1 FP (matched invalid), 1 FN (unmatched valid), 1 TN (unmatched invalid)
	matchesWithAnnotations := []MatchWithAnnotation{
		{Match: store.FindingMatch{FindingID: 1}, Annotation: store.Annotation{ID: 1, Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 2}, Annotation: store.Annotation{ID: 2, Status: store.AnnotationStatusValid}},
		{Match: store.FindingMatch{FindingID: 3}, Annotation: store.Annotation{ID: 3, Status: store.AnnotationStatusInvalid}},
	}
	unmatchedAnnotations := []store.Annotation{
		{ID: 4, Status: store.AnnotationStatusValid},
		{ID: 5, Status: store.AnnotationStatusInvalid},
	}

	m := ComputeMetrics(matchesWithAnnotations, []store.Finding{}, unmatchedAnnotations, nil)

	if m.TP != 2 {
		t.Errorf("TP = %d, want 2", m.TP)
	}
	if m.FP != 1 {
		t.Errorf("FP = %d, want 1", m.FP)
	}
	if m.FN != 1 {
		t.Errorf("FN = %d, want 1", m.FN)
	}
	if m.TN != 1 {
		t.Errorf("TN = %d, want 1", m.TN)
	}

	// Accuracy = (TP+TN)/(TP+TN+FP+FN) = (2+1)/(2+1+1+1) = 0.6
	expectedAccuracy := 0.6
	if m.Accuracy < expectedAccuracy-0.001 || m.Accuracy > expectedAccuracy+0.001 {
		t.Errorf("Accuracy = %f, want %f", m.Accuracy, expectedAccuracy)
	}
}

func TestAverageMetrics(t *testing.T) {
	m1 := &Metrics{TP: 10, FP: 4, FN: 2, TN: 1, DurationMs: 1000, MemoryPeakBytes: 100}
	m2 := &Metrics{TP: 12, FP: 6, FN: 4, TN: 1, DurationMs: 2000, MemoryPeakBytes: 200}

	// Manually set derived metrics to verify AverageMetrics recomputes them.
	m1.Precision = safeDivide(float64(m1.TP), float64(m1.TP+m1.FP))
	m1.Recall = safeDivide(float64(m1.TP), float64(m1.TP+m1.FN))
	m1.F1 = safeF1(m1.Precision, m1.Recall)
	m2.Precision = safeDivide(float64(m2.TP), float64(m2.TP+m2.FP))
	m2.Recall = safeDivide(float64(m2.TP), float64(m2.TP+m2.FN))
	m2.F1 = safeF1(m2.Precision, m2.Recall)

	avg := AverageMetrics([]*Metrics{m1, m2})

	if avg.TP != 11 {
		t.Errorf("TP = %d, want 11", avg.TP)
	}
	if avg.FP != 5 {
		t.Errorf("FP = %d, want 5", avg.FP)
	}
	if avg.FN != 3 {
		t.Errorf("FN = %d, want 3", avg.FN)
	}
	if avg.TN != 1 {
		t.Errorf("TN = %d, want 1", avg.TN)
	}
	if avg.DurationMs != 1500 {
		t.Errorf("DurationMs = %d, want 1500", avg.DurationMs)
	}
	if avg.MemoryPeakBytes != 150 {
		t.Errorf("MemoryPeakBytes = %d, want 150", avg.MemoryPeakBytes)
	}

	// Precision = 11/(11+5) = 0.6875
	if math.Abs(avg.Precision-0.6875) > 0.001 {
		t.Errorf("Precision = %f, want 0.6875", avg.Precision)
	}
	// Recall = 11/(11+3) = 0.7857
	if math.Abs(avg.Recall-0.7857) > 0.01 {
		t.Errorf("Recall = %f, want ~0.7857", avg.Recall)
	}
}

func TestAverageMetricsSingleItem(t *testing.T) {
	m := &Metrics{TP: 5, FP: 3, FN: 2, TN: 1}
	avg := AverageMetrics([]*Metrics{m})
	if avg != m {
		t.Error("single-item average should return the same pointer")
	}
}

func TestAverageMetricsEmpty(t *testing.T) {
	avg := AverageMetrics(nil)
	if avg.TP != 0 || avg.FP != 0 {
		t.Error("empty average should return zero metrics")
	}
}

func TestMedianF1Index(t *testing.T) {
	m1 := &Metrics{F1: 0.3}
	m2 := &Metrics{F1: 0.7}
	m3 := &Metrics{F1: 0.5}

	idx := MedianF1Index([]*Metrics{m1, m2, m3})
	// Sorted by F1: [0.3, 0.5, 0.7] → median index in sorted is 1 → original index of 0.5 is 2
	if idx != 2 {
		t.Errorf("MedianF1Index = %d, want 2 (F1=0.5)", idx)
	}
}

func TestMedianF1IndexSingle(t *testing.T) {
	idx := MedianF1Index([]*Metrics{{F1: 0.5}})
	if idx != 0 {
		t.Errorf("MedianF1Index single = %d, want 0", idx)
	}
}
