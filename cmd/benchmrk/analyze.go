package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <run-id>",
	Short: "Analyze a scan run",
	Long:  "Compute and display metrics (TP/FP/FN/TN/Precision/Recall/F1/Accuracy) for a scan run.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		runID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid run ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()
		svc := analysis.NewService(globalStore, nil)

		detail, _ := cmd.Flags().GetBool("detail")
		if detail {
			runDetail, err := svc.AnalyzeRunDetail(ctx, runID)
			if err != nil {
				return fmt.Errorf("analyze run detail: %w", err)
			}
			printRunDetail(runDetail)
		} else {
			metrics, err := svc.AnalyzeRun(ctx, runID)
			if err != nil {
				return fmt.Errorf("analyze run: %w", err)
			}
			printRunMetrics(metrics)
		}
		return nil
	},
}

var analyzeExperimentCmd = &cobra.Command{
	Use:   "experiment <experiment-id>",
	Short: "Analyze an experiment",
	Long:  "Compute and display aggregated metrics across all runs in an experiment, grouped by scanner and project.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		experimentID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()
		svc := analysis.NewService(globalStore, nil)

		results, err := svc.AnalyzeExperiment(ctx, experimentID)
		if err != nil {
			return fmt.Errorf("analyze experiment: %w", err)
		}

		if len(results) == 0 {
			fmt.Println("No completed runs in experiment.")
		} else {
			printExperimentMetrics(results)
		}

		// Show failed runs with error details
		runs, err := globalStore.ListRunsByExperiment(ctx, experimentID)
		if err != nil {
			return fmt.Errorf("list runs: %w", err)
		}

		var failedRuns []struct {
			RunID   int64
			Scanner string
			Project string
			Error   string
		}

		scannerCache := make(map[int64]string)
		projectCache := make(map[int64]string)

		for _, r := range runs {
			if r.Status == store.RunStatusFailed {
				scannerName := scannerCache[r.ScannerID]
				if scannerName == "" {
					if sc, err := globalStore.GetScanner(ctx, r.ScannerID); err == nil {
						scannerName = sc.Name
						scannerCache[r.ScannerID] = scannerName
					}
				}
				projectName := projectCache[r.ProjectID]
				if projectName == "" {
					if p, err := globalStore.GetProject(ctx, r.ProjectID); err == nil {
						projectName = p.Name
						projectCache[r.ProjectID] = projectName
					}
				}
				errMsg := "unknown error"
				if r.ErrorMessage.Valid && r.ErrorMessage.String != "" {
					errMsg = r.ErrorMessage.String
				}
				failedRuns = append(failedRuns, struct {
					RunID   int64
					Scanner string
					Project string
					Error   string
				}{r.ID, scannerName, projectName, errMsg})
			}
		}

		if len(failedRuns) > 0 {
			fmt.Printf("\nFailed Runs (%d):\n", len(failedRuns))
			for _, f := range failedRuns {
				fmt.Printf("  • Run %d: %s × %s\n    Error: %s\n", f.RunID, f.Scanner, f.Project, f.Error)
			}
		}

		return nil
	},
}

var compareCmd = &cobra.Command{
	Use:   "compare <scanner-a> <scanner-b> [scanner-c ...]",
	Short: "Compare two or more scanners",
	Long:  "Compare metrics of multiple scanners on a given project. The first scanner is used as the baseline for deltas.",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName, err := cmd.Flags().GetString("project")
		if err != nil {
			return fmt.Errorf("get project flag: %w", err)
		}
		if projectName == "" {
			return fmt.Errorf("--project flag is required")
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		// Lookup all scanners by name
		scannerIDs := make([]int64, 0, len(args))
		for _, name := range args {
			scanner, err := globalStore.GetScannerByName(ctx, name)
			if err != nil {
				return fmt.Errorf("scanner %q not found: %w", name, err)
			}
			scannerIDs = append(scannerIDs, scanner.ID)
		}

		// Lookup project by name
		project, err := globalStore.GetProjectByName(ctx, projectName)
		if err != nil {
			return fmt.Errorf("project %q not found: %w", projectName, err)
		}

		svc := analysis.NewService(globalStore, nil)
		svc.MinConsensus, _ = cmd.Flags().GetInt("min-consensus")
		mc, err := svc.CompareScanners(ctx, scannerIDs, project.ID)
		if err != nil {
			return fmt.Errorf("compare scanners: %w", err)
		}

		printMultiComparison(mc)

		if showCoverage, _ := cmd.Flags().GetBool("coverage"); showCoverage {
			cov, err := svc.ComputeCoverage(ctx, scannerIDs, project.ID)
			if err != nil {
				return fmt.Errorf("compute coverage: %w", err)
			}
			printCoverageOverlap(cov)
		}
		return nil
	},
}

func printRunMetrics(m *analysis.Metrics) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "METRIC\tVALUE")
	fmt.Fprintf(w, "True Positives (TP)\t%d\n", m.TP)
	fmt.Fprintf(w, "False Positives (FP)\t%d\n", m.FP)
	fmt.Fprintf(w, "False Negatives (FN)\t%d\n", m.FN)
	fmt.Fprintf(w, "True Negatives (TN)\t%d\n", m.TN)
	fmt.Fprintf(w, "Precision\t%.4f\n", m.Precision)
	fmt.Fprintf(w, "Recall\t%.4f\n", m.Recall)
	fmt.Fprintf(w, "F1 Score\t%.4f\n", m.F1)
	fmt.Fprintf(w, "Accuracy\t%.4f\n", m.Accuracy)
	if m.DurationMs > 0 {
		fmt.Fprintf(w, "Duration (ms)\t%d\n", m.DurationMs)
	}
	if m.MemoryPeakBytes > 0 {
		fmt.Fprintf(w, "Memory Peak (bytes)\t%d\n", m.MemoryPeakBytes)
	}
	w.Flush()
}

func printRunDetail(detail *analysis.RunDetail) {
	// First print normal metrics
	printRunMetrics(detail.Metrics)

	// Print annotation coverage
	fmt.Println()

	// Count stats
	triggered := 0
	missed := 0
	for _, ar := range detail.AnnotationResults {
		if ar.Matched {
			triggered++
		} else if ar.Annotation.Status == store.AnnotationStatusValid {
			missed++
		}
	}
	unmatchedFindings := 0
	for _, fr := range detail.FindingResults {
		if !fr.Matched {
			unmatchedFindings++
		}
	}

	fmt.Printf("Annotation Coverage: %d/%d triggered", triggered, len(detail.AnnotationResults))
	if missed > 0 {
		fmt.Printf(", %d missed", missed)
	}
	fmt.Println()

	// Triggered annotations table
	fmt.Println()
	fmt.Println("Triggered Annotations (detected by scanner):")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tLINE\tCWE\tCATEGORY\tSEVERITY\tMATCH\tCONFIDENCE\tRESULT")
	hasTriggered := false
	for _, ar := range detail.AnnotationResults {
		if ar.Matched {
			hasTriggered = true
			cwe := ""
			if ar.Annotation.CWEID.Valid {
				cwe = ar.Annotation.CWEID.String
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%.0f%%\t%s\n",
				ar.Annotation.FilePath, ar.Annotation.StartLine, cwe,
				ar.Annotation.Category, ar.Annotation.Severity,
				ar.MatchType, ar.Confidence*100, ar.Classification)
		}
	}
	if !hasTriggered {
		fmt.Fprintln(w, "(none)")
	}
	w.Flush()

	// Missed annotations table
	fmt.Println()
	fmt.Println("Missed Annotations (not detected by scanner):")
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tLINE\tCWE\tCATEGORY\tSEVERITY\tSTATUS\tRESULT")
	hasMissed := false
	for _, ar := range detail.AnnotationResults {
		if !ar.Matched && ar.Annotation.Status == store.AnnotationStatusValid {
			hasMissed = true
			cwe := ""
			if ar.Annotation.CWEID.Valid {
				cwe = ar.Annotation.CWEID.String
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
				ar.Annotation.FilePath, ar.Annotation.StartLine, cwe,
				ar.Annotation.Category, ar.Annotation.Severity,
				ar.Annotation.Status, ar.Classification)
		}
	}
	if !hasMissed {
		fmt.Fprintln(w, "(all valid annotations detected)")
	}
	w.Flush()

	// Unmatched findings - enriched with disposition, message, and triage stats
	if unmatchedFindings > 0 {
		triaged := 0
		tpCount := 0
		fpCount := 0
		reviewCount := 0
		for _, fr := range detail.FindingResults {
			if !fr.Matched && fr.Disposition != "" {
				triaged++
				switch fr.Disposition {
				case store.DispositionTP:
					tpCount++
				case store.DispositionFP:
					fpCount++
				case store.DispositionNeedsReview:
					reviewCount++
				}
			}
		}

		fmt.Println()
		header := fmt.Sprintf("Unmatched Findings (%d total", unmatchedFindings)
		if triaged > 0 {
			header += fmt.Sprintf(", %d triaged: %d tp, %d fp, %d needs_review", triaged, tpCount, fpCount, reviewCount)
		}
		header += "):"
		fmt.Println(header)

		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tFILE\tLINE\tCWE\tRULE\tSEVERITY\tMESSAGE\tDISPOSITION")
		for _, fr := range detail.FindingResults {
			if !fr.Matched {
				cwe := ""
				if fr.Finding.CWEID.Valid {
					cwe = fr.Finding.CWEID.String
				}
				rule := ""
				if fr.Finding.RuleID.Valid {
					rule = fr.Finding.RuleID.String
				}
				sev := ""
				if fr.Finding.Severity.Valid {
					sev = fr.Finding.Severity.String
				}
				msg := ""
				if fr.Finding.Message.Valid {
					msg = fr.Finding.Message.String
					if len(msg) > 60 {
						msg = msg[:57] + "..."
					}
				}
				disp := "(untriaged)"
				if fr.Disposition != "" {
					disp = string(fr.Disposition)
				}
				fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
					fr.Finding.ID, fr.Finding.FilePath, fr.Finding.StartLine, cwe, rule, sev, msg, disp)
			}
		}
		w.Flush()
	}
}

func printExperimentMetrics(results map[string]map[string]*analysis.Metrics) {
	// Collect all unique project names
	projectSet := make(map[string]bool)
	for _, projects := range results {
		for projectName := range projects {
			projectSet[projectName] = true
		}
	}

	projects := make([]string, 0, len(projectSet))
	for p := range projectSet {
		projects = append(projects, p)
	}

	// Print matrix header
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	header := "SCANNER"
	for _, p := range projects {
		header += "\t" + p + " (P/R/F1)"
	}
	fmt.Fprintln(w, header)

	// Print rows
	for scanner, projectMetrics := range results {
		row := scanner
		for _, p := range projects {
			if m, ok := projectMetrics[p]; ok {
				row += fmt.Sprintf("\t%.2f/%.2f/%.2f", m.Precision, m.Recall, m.F1)
			} else {
				row += "\t-"
			}
		}
		fmt.Fprintln(w, row)
	}
	w.Flush()
}

func printMultiComparison(mc *analysis.MultiComparison) {
	// Build scanner name list for header
	names := make([]string, len(mc.Entries))
	for i, e := range mc.Entries {
		names[i] = e.ScannerName
	}

	fmt.Printf("Comparing scanners on project %s (baseline: %s)\n", mc.ProjectName, names[mc.BaselineIndex])

	// Scorer consistency check. A mismatch doesn't block the output —
	// sometimes you want to see the numbers anyway — but the BEST column
	// is meaningless when the runs were graded by different logic or
	// against different ground truth.
	if !mc.Scorer.Clean() {
		fmt.Println()
		if len(mc.Scorer.MatcherVersions) > 1 {
			fmt.Printf("  ⚠ matcher version differs across runs: %s\n",
				formatScorerMap(mc.Scorer.MatcherVersions, "pre-009"))
		}
		if len(mc.Scorer.AnnotationHashes) > 1 {
			fmt.Printf("  ⚠ annotation set differs across runs: %s\n",
				formatScorerMap(mc.Scorer.AnnotationHashes, "unstamped"))
		}
		fmt.Printf("  → numbers below are not directly comparable. Run:  benchmrk rescore %s\n", mc.ProjectName)
	}

	// Show iteration counts when any scanner ran more than once. The ±σ in
	// the float rows only means something when this is visible.
	maxIter := 0
	for _, e := range mc.Entries {
		if e.Iterations > maxIter {
			maxIter = e.Iterations
		}
	}
	if maxIter > 1 {
		iters := "iterations:"
		for _, e := range mc.Entries {
			iters += fmt.Sprintf(" %s=%d", e.ScannerName, e.Iterations)
		}
		fmt.Println(iters)
	}
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Header row: METRIC | scanner1 | scanner2 | ...  | BEST
	header := "METRIC"
	for _, n := range names {
		header += "\t" + n
	}
	header += "\tBEST"
	fmt.Fprintln(w, header)

	type metricRow struct {
		label        string
		intVals      []int     // used for int metrics
		floatVals    []float64 // used for float metrics
		isFloat      bool
		higherBetter bool
	}

	rows := []metricRow{
		{label: "TP", intVals: pluck(mc.Entries, func(m *analysis.Metrics) int { return m.TP }), higherBetter: true},
		{label: "FP", intVals: pluck(mc.Entries, func(m *analysis.Metrics) int { return m.FP }), higherBetter: false},
		{label: "FN", intVals: pluck(mc.Entries, func(m *analysis.Metrics) int { return m.FN }), higherBetter: false},
		{label: "TN", intVals: pluck(mc.Entries, func(m *analysis.Metrics) int { return m.TN }), higherBetter: true},
		{label: "Precision", floatVals: pluck(mc.Entries, func(m *analysis.Metrics) float64 { return m.Precision }), isFloat: true, higherBetter: true},
		{label: "Recall", floatVals: pluck(mc.Entries, func(m *analysis.Metrics) float64 { return m.Recall }), isFloat: true, higherBetter: true},
	}

	// Per-tier recall rows appear only when metrics came via
	// ComputeVulnMetrics (Tiers non-nil) AND at least one tier has
	// vulns in it. Post-migration everything defaults to 'should',
	// so until someone re-tiers the annotation set these rows are
	// redundant with the Recall line above — show them anyway so
	// the prompt to go re-tier is visible.
	if t := mc.Entries[0].Metrics.Tiers; t != nil {
		tierRow := func(label string, pick func(*analysis.TierMetrics) (float64, int)) metricRow {
			vals := make([]float64, len(mc.Entries))
			hasAny := false
			for i, e := range mc.Entries {
				v, total := pick(e.Metrics.Tiers)
				vals[i] = v
				if total > 0 {
					hasAny = true
				}
			}
			if !hasAny {
				return metricRow{} // sentinel; skipped below
			}
			return metricRow{label: label, floatVals: vals, isFloat: true, higherBetter: true}
		}
		for _, tr := range []metricRow{
			tierRow("  Recall (must)", func(t *analysis.TierMetrics) (float64, int) { return t.Must, t.MustTotal }),
			tierRow("  Recall (should)", func(t *analysis.TierMetrics) (float64, int) { return t.Should, t.ShouldTotal }),
			tierRow("  Recall (may)", func(t *analysis.TierMetrics) (float64, int) { return t.May, t.MayTotal }),
		} {
			if tr.label != "" {
				rows = append(rows, tr)
			}
		}
	}

	rows = append(rows,
		metricRow{label: "F1", floatVals: pluck(mc.Entries, func(m *analysis.Metrics) float64 { return m.F1 }), isFloat: true, higherBetter: true},
		metricRow{label: "Accuracy", floatVals: pluck(mc.Entries, func(m *analysis.Metrics) float64 { return m.Accuracy }), isFloat: true, higherBetter: true},
		metricRow{label: "Duration (ms)", intVals: pluck(mc.Entries, func(m *analysis.Metrics) int { return int(m.DurationMs) }), higherBetter: false},
	)

	// Pull σ for the float rows when iterations allow it. Int rows
	// (TP/FP/FN/TN) are counts, not rates — showing "27 ± 1.2 true
	// positives" is more confusing than helpful, and the derived P/R/F1
	// rows carry the same uncertainty in a meaningful unit.
	stddev := func(label string) []float64 {
		if maxIter <= 1 {
			return nil
		}
		pick := map[string]func(*analysis.AggregatedMetrics) float64{
			"Precision": func(a *analysis.AggregatedMetrics) float64 { return a.PrecisionStdDev },
			"Recall":    func(a *analysis.AggregatedMetrics) float64 { return a.RecallStdDev },
			"F1":        func(a *analysis.AggregatedMetrics) float64 { return a.F1StdDev },
			"Accuracy":  func(a *analysis.AggregatedMetrics) float64 { return a.AccuracyStdDev },
		}
		fn, ok := pick[label]
		if !ok {
			return nil
		}
		out := make([]float64, len(mc.Entries))
		for i, e := range mc.Entries {
			out[i] = fn(e.Aggregated)
		}
		return out
	}

	for _, r := range rows {
		line := r.label
		if r.isFloat {
			best := bestIndex(r.floatVals, r.higherBetter)
			sd := stddev(r.label)
			for i, v := range r.floatVals {
				if sd != nil {
					line += fmt.Sprintf("\t%.4f ±%.4f", v, sd[i])
				} else {
					line += fmt.Sprintf("\t%.4f", v)
				}
			}
			// Flag the BEST when σ intervals overlap — a win that's smaller
			// than the spread is a win you can't actually claim.
			bestName := names[best]
			if sd != nil && overlap(r.floatVals, sd, best) {
				bestName += " (within σ)"
			}
			line += "\t" + bestName
		} else {
			best := bestIndex(r.intVals, r.higherBetter)
			for _, v := range r.intVals {
				line += fmt.Sprintf("\t%d", v)
			}
			line += "\t" + names[best]
		}
		fmt.Fprintln(w, line)
	}
	w.Flush()
}

// overlap reports whether any non-best entry's ±σ interval intersects the
// best entry's interval. Rough — assumes symmetric intervals, no
// Bonferroni — but enough to flag "don't trust this ranking" in a CLI.
func overlap(means, stddevs []float64, best int) bool {
	bLo, bHi := means[best]-stddevs[best], means[best]+stddevs[best]
	for i := range means {
		if i == best {
			continue
		}
		lo, hi := means[i]-stddevs[i], means[i]+stddevs[i]
		if lo <= bHi && bLo <= hi {
			return true
		}
	}
	return false
}

// formatScorerMap renders {key: [runIDs]} concisely for the warning lines.
// The empty-string key (unstamped runs) gets a readable label.
func formatScorerMap(m map[string][]int64, emptyLabel string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		label := k
		if label == "" {
			label = emptyLabel
		}
		out += fmt.Sprintf("%s→runs%v", label, m[k])
	}
	return out
}

func pluck[T any](entries []analysis.ScannerComparisonEntry, fn func(*analysis.Metrics) T) []T {
	vals := make([]T, len(entries))
	for i, e := range entries {
		vals[i] = fn(e.Metrics)
	}
	return vals
}

func bestIndex[T cmp.Ordered](vals []T, higherBetter bool) int {
	best := 0
	for i := 1; i < len(vals); i++ {
		if higherBetter && vals[i] > vals[best] {
			best = i
		} else if !higherBetter && vals[i] < vals[best] {
			best = i
		}
	}
	return best
}

// printCoverageOverlap renders the "do I need all these tools" section
// below the main metrics table. The two numbers that matter most land
// first: how much recall the union buys over the best single tool, and
// which vulns nobody catches. Then the per-scanner cost-of-dropping
// table, which is where the actual decision lives.
func printCoverageOverlap(cov *analysis.CoverageOverlap) {
	fmt.Println("\n" + strings.Repeat("─", 60))
	fmt.Println("COVERAGE OVERLAP  (valid vulnerabilities only)")
	fmt.Println()

	uplift := cov.UnionRecall - cov.BestSingleRecall
	fmt.Printf("  Union recall:       %.4f   (best single: %.4f, %s)\n",
		cov.UnionRecall, cov.BestSingleRecall, cov.BestSingleName)
	if uplift < 0.001 {
		fmt.Printf("  → running all %d gains nothing over %s alone\n",
			len(cov.ScannerNames), cov.BestSingleName)
	} else {
		fmt.Printf("  → running all %d scanners gains +%.4f recall over the best one alone\n",
			len(cov.ScannerNames), uplift)
	}
	fmt.Printf("  Union FP ceiling:   ≤%d       (sum of per-scanner FP; real overlap unknown)\n",
		cov.UnionFPCeiling)
	fmt.Println()

	fmt.Printf("  Caught by all   %4d   %s\n", len(cov.CaughtByAll), tierSummary(cov.CaughtByAll))
	fmt.Printf("  Caught by none  %4d   %s   ← blind spots regardless of which you pick\n",
		len(cov.CaughtByNone), tierSummary(cov.CaughtByNone))
	if tc := analysis.TierCount(cov.CaughtByNone); tc.Must > 0 {
		// must-tier blind spots are the headline. List them inline —
		// these are the bugs every tool in the set misses that any
		// competent tool should find. That's either a ground-truth
		// error or a hole in every scanner's rules.
		fmt.Println("    must-tier gaps:")
		for _, v := range cov.CaughtByNone {
			if v.Criticality == "must" {
				fmt.Printf("      %s\n", v.Name)
			}
		}
	}
	fmt.Println()

	// Marginal contribution. The vuln names matter here — "you lose 2
	// things" is abstract; "you lose jwt-alg-none" is a decision.
	fmt.Println("MARGINAL CONTRIBUTION  (dropping this scanner loses these — nobody else catches them)")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, m := range cov.Marginal {
		if len(m.Unique) == 0 {
			fmt.Fprintf(w, "  %s\t0\t\t← redundant given the others\n", m.ScannerName)
			continue
		}
		fmt.Fprintf(w, "  %s\t%d\t%s\t%s\n",
			m.ScannerName, len(m.Unique), tierSummary(m.Unique), vulnNameList(m.Unique, 4))
	}
	w.Flush()

	if len(cov.Flaky) > 0 {
		fmt.Println("\nFLAKY COVERAGE  (caught in some iterations, not all — distrust first)")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, f := range cov.Flaky {
			fmt.Fprintf(w, "  %s\t%s\t%d/%d iterations\n",
				f.ScannerName, f.Vuln.Name, f.HitRuns, f.TotalRuns)
		}
		w.Flush()
	}
}

// tierSummary renders "[must:2 should:1]", omitting zero buckets.
// Empty slice → "" so the summary disappears rather than "[must:0 ...]".
func tierSummary(vs []store.Vulnerability) string {
	tc := analysis.TierCount(vs)
	if tc.Must+tc.Should+tc.May == 0 {
		return ""
	}
	var parts []string
	if tc.Must > 0 {
		parts = append(parts, fmt.Sprintf("must:%d", tc.Must))
	}
	if tc.Should > 0 {
		parts = append(parts, fmt.Sprintf("should:%d", tc.Should))
	}
	if tc.May > 0 {
		parts = append(parts, fmt.Sprintf("may:%d", tc.May))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// vulnNameList renders up to limit names, then "(+N more)". The vulns
// are already tier-sorted by ComputeCoverage, so the first few are the
// most important ones — if we're going to truncate, we truncate may-tier.
func vulnNameList(vs []store.Vulnerability, limit int) string {
	names := make([]string, 0, limit)
	for i, v := range vs {
		if i >= limit {
			names = append(names, fmt.Sprintf("(+%d more)", len(vs)-limit))
			break
		}
		names = append(names, v.Name)
	}
	return strings.Join(names, ", ")
}

func init() {
	// Analyze flags
	analyzeCmd.Flags().Bool("detail", false, "show per-annotation detail (triggered/missed)")

	// Compare flags
	compareCmd.Flags().StringP("project", "p", "", "project name to compare on (required)")
	compareCmd.Flags().Int("min-consensus", 0, "ignore vulnerabilities annotated by fewer than N people (0 = no filter)")
	compareCmd.Flags().Bool("coverage", false, "show coverage overlap: which vulns each scanner uniquely catches, union recall, blind spots")

	// Wire up command hierarchy
	analyzeCmd.AddCommand(analyzeExperimentCmd)

	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(compareCmd)
}
