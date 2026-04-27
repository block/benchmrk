package analysis

import (
	"math"
	"sort"

	"github.com/block/benchmrk/internal/store"
)

// IsPositiveAnnotation returns true if the annotation represents a real vulnerability.
func IsPositiveAnnotation(status store.AnnotationStatus) bool {
	return status == store.AnnotationStatusValid
}

// IsNegativeAnnotation returns true if the annotation represents a non-vulnerability.
func IsNegativeAnnotation(status store.AnnotationStatus) bool {
	return status == store.AnnotationStatusInvalid
}

// Metrics contains performance metrics for a scan run.
type Metrics struct {
	// Classification counts
	TP int // True positives: finding matched a valid annotation
	FP int // False positives: finding matched an invalid annotation, or unmatched finding
	FN int // False negatives: valid annotation not matched by any finding
	TN int // True negatives: invalid annotation not matched by any finding

	// Derived metrics
	Precision float64 // TP / (TP + FP), 0 if division by zero
	Recall    float64 // TP / (TP + FN), 0 if division by zero
	F1        float64 // 2 * (P * R) / (P + R), 0 if division by zero
	Accuracy  float64 // (TP + TN) / (TP + TN + FP + FN), 0 if division by zero

	// Duration statistics (milliseconds)
	DurationMs int64

	// Memory statistics (bytes)
	MemoryPeakBytes int64

	// Tiers breaks recall down by vulnerability criticality. Nil when
	// metrics were computed via the per-annotation path (ComputeMetrics);
	// populated by ComputeVulnMetrics. The printer checks nil and
	// suppresses the tier rows.
	Tiers *TierMetrics
}

// CategoryMetrics contains per-category performance metrics.
type CategoryMetrics struct {
	Category  string
	TP        int
	FP        int
	FN        int
	TN        int
	Precision float64
	Recall    float64
	F1        float64
	Accuracy  float64
}

// TierMetrics breaks recall down by vulnerability criticality. A tool at
// 0.85 overall recall that missed the alg:none JWT bypass (a 'must') is
// worse than one at 0.80 that caught it and missed five hardening gaps
// ('may'). This makes that visible.
type TierMetrics struct {
	// Recall per tier: TP / (TP+FN) where both counts are restricted to
	// vulns at that criticality. Precision is NOT per-tier — findings
	// don't have a criticality, so "FPs at tier X" is meaningless.
	Must   float64
	Should float64
	May    float64

	// Counts behind the rates, for "N/A" detection in the printer —
	// 0/0 should show as "-", not 0.0000.
	MustTotal, ShouldTotal, MayTotal int
	MustTP, ShouldTP, MayTP          int
}

// ComputeVulnMetrics counts at the vulnerability level. A vulnerability
// with six evidence locations, one of which was matched, scores one TP —
// not six, not one-plus-five-group-rescued. This is the accounting
// change that makes pre-010 and post-010 F1 numbers incomparable.
//
//	satisfied    vulns where at least one evidence row matched
//	unsatisfied  vulns where zero evidence rows matched
//	unmatched    findings that matched no evidence row at all
//	dispositions manual TP/FP overrides for unmatched findings
//
// No groups parameter. The vulnerability→evidence structure IS the
// group — that's the whole point of the inversion.
func ComputeVulnMetrics(
	satisfied, unsatisfied []store.Vulnerability,
	unmatched []store.Finding,
	dispositions map[int64]store.FindingDisposition,
) *Metrics {
	m := Metrics{Tiers: &TierMetrics{}}

	// Satisfied vulns: valid → TP, invalid → matched-FP. While we're
	// iterating, accumulate tier counts.
	for _, v := range satisfied {
		vs := store.AnnotationStatus(v.Status)
		if IsPositiveAnnotation(vs) {
			m.TP++
			tierTP(m.Tiers, v.Criticality)
		} else if IsNegativeAnnotation(vs) {
			m.FP++
		}
		tierTotal(m.Tiers, v.Criticality, vs)
	}

	// Unsatisfied vulns: valid → FN, invalid → TN.
	for _, v := range unsatisfied {
		vs := store.AnnotationStatus(v.Status)
		if IsPositiveAnnotation(vs) {
			m.FN++
		} else if IsNegativeAnnotation(vs) {
			m.TN++
		}
		tierTotal(m.Tiers, v.Criticality, vs)
	}

	// Unmatched findings: FP unless a human dispositioned them otherwise.
	// Same logic as the per-annotation path; findings are findings.
	for _, f := range unmatched {
		if d, ok := dispositions[f.ID]; ok && d.Disposition == store.DispositionTP {
			m.TP++
			continue
		}
		m.FP++
	}

	m.Precision = safeDivide(float64(m.TP), float64(m.TP+m.FP))
	m.Recall = safeDivide(float64(m.TP), float64(m.TP+m.FN))
	m.F1 = safeF1(m.Precision, m.Recall)
	m.Accuracy = safeDivide(float64(m.TP+m.TN), float64(m.TP+m.TN+m.FP+m.FN))

	m.Tiers.Must = safeDivide(float64(m.Tiers.MustTP), float64(m.Tiers.MustTotal))
	m.Tiers.Should = safeDivide(float64(m.Tiers.ShouldTP), float64(m.Tiers.ShouldTotal))
	m.Tiers.May = safeDivide(float64(m.Tiers.MayTP), float64(m.Tiers.MayTotal))

	return &m
}

func tierTP(t *TierMetrics, crit string) {
	switch crit {
	case "must":
		t.MustTP++
	case "should":
		t.ShouldTP++
	case "may":
		t.MayTP++
	}
}

func tierTotal(t *TierMetrics, crit string, status store.AnnotationStatus) {
	// Totals count valid vulns only — invalid vulns have no recall
	// denominator. They're TN/matched-FP, which is a precision concern.
	if !IsPositiveAnnotation(status) {
		return
	}
	switch crit {
	case "must":
		t.MustTotal++
	case "should":
		t.ShouldTotal++
	case "may":
		t.MayTotal++
	}
}

// RunMetrics holds metrics for a single run, used for aggregation.
type RunMetrics struct {
	Metrics
	RunID     int64
	ScannerID int64
	ProjectID int64
	Iteration int
}

// AggregatedMetrics contains aggregate statistics across multiple runs.
type AggregatedMetrics struct {
	Count int

	// Precision stats
	PrecisionMean   float64
	PrecisionMedian float64
	PrecisionStdDev float64

	// Recall stats
	RecallMean   float64
	RecallMedian float64
	RecallStdDev float64

	// F1 stats
	F1Mean   float64
	F1Median float64
	F1StdDev float64

	// Accuracy stats
	AccuracyMean   float64
	AccuracyMedian float64
	AccuracyStdDev float64

	// Duration stats (milliseconds)
	DurationMean   float64
	DurationMedian float64
	DurationStdDev float64

	// Memory stats (bytes)
	MemoryMean   float64
	MemoryMedian float64
	MemoryStdDev float64
}

// MatchWithAnnotation pairs a FindingMatch with its associated Annotation for category lookups.
type MatchWithAnnotation struct {
	Match      store.FindingMatch
	Annotation store.Annotation
}

// ComputeMetrics calculates TP, FP, FN, TN, precision, recall, F1, and accuracy from matches and unmatched items.
//
// Classification rules:
//   - TP = finding matched a valid annotation (real vulnerability found)
//   - FP = finding matched an invalid annotation, or unmatched finding (false alarm)
//   - FN = valid annotation not matched by any finding (missed vulnerability)
//   - TN = invalid annotation not matched by any finding (correctly ignored)
func ComputeMetrics(matchesWithAnnotations []MatchWithAnnotation, unmatchedFindings []store.Finding, unmatchedAnnotations []store.Annotation, dispositions map[int64]store.FindingDisposition) *Metrics {
	m := &Metrics{}

	// Count TP and matched-FP from matches
	for _, mwa := range matchesWithAnnotations {
		if IsPositiveAnnotation(mwa.Annotation.Status) {
			m.TP++
		} else if IsNegativeAnnotation(mwa.Annotation.Status) {
			m.FP++
		}
	}

	// Unmatched findings: check dispositions
	for _, f := range unmatchedFindings {
		if d, ok := dispositions[f.ID]; ok {
			switch d.Disposition {
			case store.DispositionTP:
				m.TP++
			case store.DispositionFP:
				m.FP++
			// "needs_review" findings are counted as FP (conservative default)
			default:
				m.FP++
			}
		} else {
			// No disposition = FP (backward compatible)
			m.FP++
		}
	}

	// Unmatched annotations: valid → FN, invalid → TN. Group rescue
	// happens upstream — PropagateGroups writes match_type='group'
	// rows at scoring time, so group-rescued annotations have match
	// rows and never reach this list.
	for _, a := range unmatchedAnnotations {
		if IsPositiveAnnotation(a.Status) {
			m.FN++
		} else if IsNegativeAnnotation(a.Status) {
			m.TN++
		}
	}

	// Compute derived metrics
	m.Precision = safeDivide(float64(m.TP), float64(m.TP+m.FP))
	m.Recall = safeDivide(float64(m.TP), float64(m.TP+m.FN))
	m.F1 = safeF1(m.Precision, m.Recall)
	m.Accuracy = safeDivide(float64(m.TP+m.TN), float64(m.TP+m.TN+m.FP+m.FN))

	return m
}

// ComputeCategoryMetrics groups metrics by vulnerability category.
func ComputeCategoryMetrics(matchesWithAnnotations []MatchWithAnnotation, unmatchedFindings []store.Finding, unmatchedAnnotations []store.Annotation, dispositions map[int64]store.FindingDisposition) map[string]*CategoryMetrics {
	categories := make(map[string]*CategoryMetrics)

	getOrCreate := func(cat string) *CategoryMetrics {
		if cm, ok := categories[cat]; ok {
			return cm
		}
		cm := &CategoryMetrics{Category: cat}
		categories[cat] = cm
		return cm
	}

	// Count TP and matched-FP from matches by annotation category
	for _, mwa := range matchesWithAnnotations {
		cat := mwa.Annotation.Category
		if cat == "" {
			cat = "unknown"
		}
		cm := getOrCreate(cat)
		if IsPositiveAnnotation(mwa.Annotation.Status) {
			cm.TP++
		} else if IsNegativeAnnotation(mwa.Annotation.Status) {
			cm.FP++
		}
	}

	// Unmatched findings: check dispositions, categorize by finding's CWE
	for _, f := range unmatchedFindings {
		cat := "unknown"
		if f.CWEID.Valid && f.CWEID.String != "" {
			cat = GetCategory(f.CWEID.String)
		}
		cm := getOrCreate(cat)
		if d, ok := dispositions[f.ID]; ok {
			switch d.Disposition {
			case store.DispositionTP:
				cm.TP++
			case store.DispositionFP:
				cm.FP++
			default:
				cm.FP++
			}
		} else {
			cm.FP++
		}
	}

	// Unmatched annotations: valid → FN, invalid → TN
	for _, a := range unmatchedAnnotations {
		cat := a.Category
		if cat == "" {
			cat = "unknown"
		}
		if IsPositiveAnnotation(a.Status) {
			cm := getOrCreate(cat)
			cm.FN++
		} else if IsNegativeAnnotation(a.Status) {
			cm := getOrCreate(cat)
			cm.TN++
		}
	}

	// Compute derived metrics for each category
	for _, cm := range categories {
		cm.Precision = safeDivide(float64(cm.TP), float64(cm.TP+cm.FP))
		cm.Recall = safeDivide(float64(cm.TP), float64(cm.TP+cm.FN))
		cm.F1 = safeF1(cm.Precision, cm.Recall)
		cm.Accuracy = safeDivide(float64(cm.TP+cm.TN), float64(cm.TP+cm.TN+cm.FP+cm.FN))
	}

	return categories
}

// AggregateRunMetrics computes aggregate statistics (mean, median, stddev) across multiple runs.
func AggregateRunMetrics(runs []RunMetrics) *AggregatedMetrics {
	if len(runs) == 0 {
		return &AggregatedMetrics{}
	}

	agg := &AggregatedMetrics{Count: len(runs)}

	precisions := make([]float64, len(runs))
	recalls := make([]float64, len(runs))
	f1s := make([]float64, len(runs))
	accuracies := make([]float64, len(runs))
	durations := make([]float64, len(runs))
	memories := make([]float64, len(runs))

	for i, r := range runs {
		precisions[i] = r.Precision
		recalls[i] = r.Recall
		f1s[i] = r.F1
		accuracies[i] = r.Accuracy
		durations[i] = float64(r.DurationMs)
		memories[i] = float64(r.MemoryPeakBytes)
	}

	agg.PrecisionMean, agg.PrecisionMedian, agg.PrecisionStdDev = computeStats(precisions)
	agg.RecallMean, agg.RecallMedian, agg.RecallStdDev = computeStats(recalls)
	agg.F1Mean, agg.F1Median, agg.F1StdDev = computeStats(f1s)
	agg.AccuracyMean, agg.AccuracyMedian, agg.AccuracyStdDev = computeStats(accuracies)
	agg.DurationMean, agg.DurationMedian, agg.DurationStdDev = computeStats(durations)
	agg.MemoryMean, agg.MemoryMedian, agg.MemoryStdDev = computeStats(memories)

	return agg
}

// AverageMetrics computes the mean of multiple Metrics, averaging TP/FP/FN/TN
// counts (rounded) and duration/memory, then recomputing derived metrics.
func AverageMetrics(metricsList []*Metrics) *Metrics {
	if len(metricsList) == 0 {
		return &Metrics{}
	}
	if len(metricsList) == 1 {
		return metricsList[0]
	}

	n := float64(len(metricsList))
	var sumTP, sumFP, sumFN, sumTN float64
	var sumDuration, sumMemory float64

	for _, m := range metricsList {
		sumTP += float64(m.TP)
		sumFP += float64(m.FP)
		sumFN += float64(m.FN)
		sumTN += float64(m.TN)
		sumDuration += float64(m.DurationMs)
		sumMemory += float64(m.MemoryPeakBytes)
	}

	avg := &Metrics{
		TP:              int(math.Round(sumTP / n)),
		FP:              int(math.Round(sumFP / n)),
		FN:              int(math.Round(sumFN / n)),
		TN:              int(math.Round(sumTN / n)),
		DurationMs:      int64(math.Round(sumDuration / n)),
		MemoryPeakBytes: int64(math.Round(sumMemory / n)),
	}
	avg.Precision = safeDivide(float64(avg.TP), float64(avg.TP+avg.FP))
	avg.Recall = safeDivide(float64(avg.TP), float64(avg.TP+avg.FN))
	avg.F1 = safeF1(avg.Precision, avg.Recall)
	avg.Accuracy = safeDivide(float64(avg.TP+avg.TN), float64(avg.TP+avg.TN+avg.FP+avg.FN))

	// Tiers: average the counts, recompute the rates. Without this the
	// tier-recall rows vanish at iterations≥2 — exactly when variance
	// data appears and the rows would be most useful. Only carried
	// through when every run came via ComputeVulnMetrics; if any run
	// used the per-annotation path (Tiers==nil), drop tiers entirely
	// rather than average an incomplete set.
	avg.Tiers = averageTiers(metricsList)

	return avg
}

func averageTiers(ms []*Metrics) *TierMetrics {
	var sum TierMetrics
	for _, m := range ms {
		if m.Tiers == nil {
			return nil
		}
		sum.MustTP += m.Tiers.MustTP
		sum.MustTotal += m.Tiers.MustTotal
		sum.ShouldTP += m.Tiers.ShouldTP
		sum.ShouldTotal += m.Tiers.ShouldTotal
		sum.MayTP += m.Tiers.MayTP
		sum.MayTotal += m.Tiers.MayTotal
	}
	// The *Total fields are constant across iterations of the same
	// project (same ground truth each time), so sum/n == any single
	// run's value. The *TP fields vary — iteration 1 might catch a
	// must-tier vuln iteration 2 misses. Averaging both and recomputing
	// from the averaged counts matches how the headline TP/FN are
	// handled above.
	n := float64(len(ms))
	r := func(x int) int { return int(math.Round(float64(x) / n)) }
	out := &TierMetrics{
		MustTP: r(sum.MustTP), MustTotal: r(sum.MustTotal),
		ShouldTP: r(sum.ShouldTP), ShouldTotal: r(sum.ShouldTotal),
		MayTP: r(sum.MayTP), MayTotal: r(sum.MayTotal),
	}
	out.Must = safeDivide(float64(out.MustTP), float64(out.MustTotal))
	out.Should = safeDivide(float64(out.ShouldTP), float64(out.ShouldTotal))
	out.May = safeDivide(float64(out.MayTP), float64(out.MayTotal))
	return out
}

// MedianF1Index returns the index of the metric with the median F1 score.
// For even-length slices, returns the lower-median index.
func MedianF1Index(metricsList []*Metrics) int {
	if len(metricsList) <= 1 {
		return 0
	}
	type indexed struct {
		f1  float64
		idx int
	}
	items := make([]indexed, len(metricsList))
	for i, m := range metricsList {
		items[i] = indexed{f1: m.F1, idx: i}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].f1 < items[j].f1
	})
	return items[len(items)/2].idx
}

// safeDivide returns a/b, or 0 if b is 0.
func safeDivide(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// safeF1 computes F1 = 2 * P * R / (P + R), or 0 if P + R is 0.
func safeF1(precision, recall float64) float64 {
	sum := precision + recall
	if sum == 0 {
		return 0
	}
	return 2 * precision * recall / sum
}

// computeStats calculates mean, median, and standard deviation for a slice of values.
func computeStats(values []float64) (mean, median, stddev float64) {
	n := len(values)
	if n == 0 {
		return 0, 0, 0
	}

	// Mean
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(n)

	// Median
	sorted := make([]float64, n)
	copy(sorted, values)
	sort.Float64s(sorted)
	if n%2 == 0 {
		median = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		median = sorted[n/2]
	}

	// Standard deviation
	var sumSquares float64
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	stddev = math.Sqrt(sumSquares / float64(n))

	return mean, median, stddev
}
