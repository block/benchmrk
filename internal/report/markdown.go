package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// FormatMarkdown writes the report as human-readable Markdown.
func FormatMarkdown(data *ReportData, w io.Writer) error {
	var b strings.Builder

	b.WriteString("# ")
	b.WriteString(data.Title)
	b.WriteString("\n\n")

	b.WriteString("**Generated:** ")
	b.WriteString(data.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	b.WriteString("\n\n")

	writeExperimentSection(&b, data)
	writeSummarySection(&b, data)
	writeScannerResultsSection(&b, data)
	writeAnnotationCoverageDetails(&b, data)
	writeCategoryBreakdownSection(&b, data)

	if data.Comparison != nil {
		writeComparisonSection(&b, data.Comparison)
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

func writeExperimentSection(b *strings.Builder, data *ReportData) {
	b.WriteString("## Experiment\n\n")
	b.WriteString(fmt.Sprintf("- **Name:** %s\n", data.Experiment.Name))
	if data.Experiment.Description != "" {
		b.WriteString(fmt.Sprintf("- **Description:** %s\n", data.Experiment.Description))
	}
	b.WriteString(fmt.Sprintf("- **Iterations:** %d\n", data.Experiment.Iterations))
	b.WriteString(fmt.Sprintf("- **Scanners:** %d\n", len(data.Scanners)))
	b.WriteString(fmt.Sprintf("- **Projects:** %d\n", len(data.Projects)))
	b.WriteString("\n")
}

func writeSummarySection(b *strings.Builder, data *ReportData) {
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total Runs | %d |\n", data.Summary.TotalRuns))
	b.WriteString(fmt.Sprintf("| Total Findings | %d |\n", data.Summary.TotalFindings))
	b.WriteString(fmt.Sprintf("| True Positives | %d |\n", data.Summary.TotalTP))
	b.WriteString(fmt.Sprintf("| False Positives | %d |\n", data.Summary.TotalFP))
	b.WriteString(fmt.Sprintf("| False Negatives | %d |\n", data.Summary.TotalFN))
	b.WriteString(fmt.Sprintf("| True Negatives | %d |\n", data.Summary.TotalTN))
	b.WriteString(fmt.Sprintf("| Avg Precision | %.2f%% |\n", data.Summary.AvgPrecision*100))
	b.WriteString(fmt.Sprintf("| Avg Recall | %.2f%% |\n", data.Summary.AvgRecall*100))
	b.WriteString(fmt.Sprintf("| Avg F1 | %.2f%% |\n", data.Summary.AvgF1*100))
	b.WriteString(fmt.Sprintf("| Avg Accuracy | %.2f%% |\n", data.Summary.AvgAccuracy*100))
	b.WriteString("\n")
}

func writeScannerResultsSection(b *strings.Builder, data *ReportData) {
	b.WriteString("## Scanner Results\n\n")

	if len(data.ByScanner) == 0 {
		b.WriteString("*No scanner results available.*\n\n")
		return
	}

	b.WriteString("| Scanner | Runs | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |\n")
	b.WriteString("|---------|------|----|----|----|----|-----------|--------|----|----------|\n")

	for _, sr := range data.ByScanner {
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %.2f%% | %.2f%% | %.2f%% | %.2f%% |\n",
			sr.ScannerName,
			sr.RunCount,
			sr.Metrics.TP,
			sr.Metrics.FP,
			sr.Metrics.FN,
			sr.Metrics.TN,
			sr.Metrics.Precision*100,
			sr.Metrics.Recall*100,
			sr.Metrics.F1*100,
			sr.Metrics.Accuracy*100,
		))
	}
	b.WriteString("\n")

	for _, sr := range data.ByScanner {
		if len(sr.ByProject) == 0 {
			continue
		}

		b.WriteString(fmt.Sprintf("### %s - Per Project\n\n", sr.ScannerName))
		b.WriteString("| Project | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy | Duration (ms) |\n")
		b.WriteString("|---------|----|----|----|----|-----------|--------|----|----------|---------------|\n")

		for _, pr := range sr.ByProject {
			b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %.2f%% | %.2f%% | %.2f%% | %.2f%% | %d |\n",
				pr.ProjectName,
				pr.TP,
				pr.FP,
				pr.FN,
				pr.TN,
				pr.Precision*100,
				pr.Recall*100,
				pr.F1*100,
				pr.Accuracy*100,
				pr.DurationMs,
			))
		}
		b.WriteString("\n")
	}
}

func writeCategoryBreakdownSection(b *strings.Builder, data *ReportData) {
	b.WriteString("## Category Breakdown\n\n")

	if len(data.ByCategory) == 0 {
		b.WriteString("*No category data available.*\n\n")
		return
	}

	categories := make([]CategoryStats, len(data.ByCategory))
	copy(categories, data.ByCategory)
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Category < categories[j].Category
	})

	b.WriteString("| Category | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |\n")
	b.WriteString("|----------|----|----|----|----|-----------|--------|----|----------|\n")

	for _, cs := range categories {
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %.2f%% | %.2f%% | %.2f%% | %.2f%% |\n",
			cs.Category,
			cs.TP,
			cs.FP,
			cs.FN,
			cs.TN,
			cs.Precision*100,
			cs.Recall*100,
			cs.F1*100,
			cs.Accuracy*100,
		))
	}
	b.WriteString("\n")
}

func writeAnnotationCoverageDetails(b *strings.Builder, data *ReportData) {
	for _, sr := range data.ByScanner {
		for _, pr := range sr.ByProject {
			if len(pr.Annotations) == 0 {
				continue
			}

			b.WriteString(fmt.Sprintf("#### %s / %s — Annotation Coverage\n\n", sr.ScannerName, pr.ProjectName))

			// Show triggered (matched) annotations
			b.WriteString("**Triggered Annotations (detected by scanner):**\n\n")
			b.WriteString("| File | Line | CWE | Category | Severity | Match | Confidence | Result |\n")
			b.WriteString("|------|------|-----|----------|----------|-------|------------|--------|\n")
			hasTriggered := false
			for _, ac := range pr.Annotations {
				if ac.Matched {
					hasTriggered = true
					b.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s | %s | %.0f%% | %s |\n",
						ac.FilePath, ac.StartLine, ac.CWEID, ac.Category, ac.Severity, ac.MatchType, ac.Confidence*100, ac.Classification))
				}
			}
			if !hasTriggered {
				b.WriteString("| — | — | — | — | — | — | — | *none detected* |\n")
			}
			b.WriteString("\n")

			// Show missed (unmatched valid) annotations
			b.WriteString("**Missed Annotations (not detected by scanner):**\n\n")
			b.WriteString("| File | Line | CWE | Category | Severity | Status | Result |\n")
			b.WriteString("|------|------|-----|----------|----------|--------|--------|\n")
			hasMissed := false
			for _, ac := range pr.Annotations {
				if !ac.Matched && ac.Status == "valid" {
					hasMissed = true
					b.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s | %s | %s |\n",
						ac.FilePath, ac.StartLine, ac.CWEID, ac.Category, ac.Severity, ac.Status, ac.Classification))
				}
			}
			if !hasMissed {
				b.WriteString("| — | — | — | — | — | — | *all detected* |\n")
			}
			b.WriteString("\n")

			// Show unmatched findings (false positives with no annotation)
			if len(pr.UnmatchedFindings) > 0 {
				b.WriteString("**Unmatched Findings (no corresponding annotation):**\n\n")
				b.WriteString("| File | Line | CWE | Rule | Severity |\n")
				b.WriteString("|------|------|-----|------|----------|\n")
				for _, uf := range pr.UnmatchedFindings {
					b.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s |\n",
						uf.FilePath, uf.StartLine, uf.CWEID, uf.RuleID, uf.Severity))
				}
				b.WriteString("\n")
			}
		}
	}
}

func writeComparisonSection(b *strings.Builder, comp *ComparisonData) {
	if len(comp.Entries) == 0 {
		return
	}

	b.WriteString("## Scanner Comparison\n\n")
	b.WriteString(fmt.Sprintf("Comparing %d scanners (baseline: %s)\n\n",
		len(comp.Entries), comp.Entries[comp.BaselineIndex].Scanner.Name))

	// Header row
	b.WriteString("| Metric |")
	for _, e := range comp.Entries {
		b.WriteString(fmt.Sprintf(" %s |", e.Scanner.Name))
	}
	b.WriteString("\n")

	// Separator row
	b.WriteString("|--------|")
	for _, e := range comp.Entries {
		b.WriteString(strings.Repeat("-", len(e.Scanner.Name)+2))
		b.WriteString("|")
	}
	b.WriteString("\n")

	// Metric rows
	type metricRow struct {
		label   string
		valFn   func(ComparisonMetrics) string
		deltaFn func(*MetricDeltas) string
	}
	rows := []metricRow{
		{"Precision", func(m ComparisonMetrics) string { return fmt.Sprintf("%.2f%%", m.Precision*100) },
			func(d *MetricDeltas) string { return fmt.Sprintf("%+.2f%%", d.Precision*100) }},
		{"Recall", func(m ComparisonMetrics) string { return fmt.Sprintf("%.2f%%", m.Recall*100) },
			func(d *MetricDeltas) string { return fmt.Sprintf("%+.2f%%", d.Recall*100) }},
		{"F1", func(m ComparisonMetrics) string { return fmt.Sprintf("%.2f%%", m.F1*100) },
			func(d *MetricDeltas) string { return fmt.Sprintf("%+.2f%%", d.F1*100) }},
		{"Accuracy", func(m ComparisonMetrics) string { return fmt.Sprintf("%.2f%%", m.Accuracy*100) },
			func(d *MetricDeltas) string { return fmt.Sprintf("%+.2f%%", d.Accuracy*100) }},
		{"Duration (ms)", func(m ComparisonMetrics) string { return fmt.Sprintf("%.0f", m.DurationMs) },
			func(d *MetricDeltas) string { return fmt.Sprintf("%+.0f", d.DurationMs) }},
	}

	for _, row := range rows {
		b.WriteString(fmt.Sprintf("| %s |", row.label))
		for _, e := range comp.Entries {
			val := row.valFn(e.Metrics)
			if e.Delta != nil {
				val += " (" + row.deltaFn(e.Delta) + ")"
			}
			b.WriteString(fmt.Sprintf(" %s |", val))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if len(comp.ByProject) > 0 {
		b.WriteString("### Per-Project Comparison\n\n")

		// Header
		b.WriteString("| Project |")
		for _, e := range comp.Entries {
			b.WriteString(fmt.Sprintf(" %s F1 |", e.Scanner.Name))
		}
		b.WriteString("\n")

		// Separator
		b.WriteString("|---------|")
		for _, e := range comp.Entries {
			b.WriteString(strings.Repeat("-", len(e.Scanner.Name)+5))
			b.WriteString("|")
		}
		b.WriteString("\n")

		for _, pc := range comp.ByProject {
			b.WriteString(fmt.Sprintf("| %s |", pc.ProjectName))
			for _, pe := range pc.Entries {
				val := fmt.Sprintf("%.2f%%", pe.F1*100)
				if pe.DeltaF1 != nil {
					val += fmt.Sprintf(" (%+.2f%%)", *pe.DeltaF1*100)
				}
				b.WriteString(fmt.Sprintf(" %s |", val))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
}
