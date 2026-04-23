package analysis

import (
	"context"
	"fmt"
	"sort"

	"github.com/block/benchmrk/internal/store"
)

// CoverageOverlap answers the tool-selection question that compare's
// headline metrics can't: if I run all these scanners and OR their
// findings, how much more do I catch than running just the best one?
// And for each scanner, what do I *lose* if I drop it?
//
// The data path is per-vuln: which subset of scanners caught it (in at
// least one iteration). A vuln caught by every scanner is the floor —
// you get that no matter which you pick. A vuln caught by exactly one
// scanner is that scanner's marginal contribution — drop the scanner,
// lose the vuln. A vuln caught by nobody is a blind spot regardless.
//
// Only status='valid' vulnerabilities count. An 'invalid' decoy caught
// by all scanners isn't coverage, it's a shared false positive.
type CoverageOverlap struct {
	ScannerNames []string // index aligns with the bitmask in VulnCoverage.CaughtBy

	// The four partitions of valid ground truth.
	CaughtByAll  []store.Vulnerability // floor — every scanner finds these
	CaughtByNone []store.Vulnerability // gaps — no scanner in the set finds these
	CaughtBySome []VulnCoverage        // the interesting middle

	// Marginal[i] = vulns that ScannerNames[i] catches and no other
	// scanner in the set catches. This is the cost of dropping it.
	// Empty slice → redundant: everything this scanner finds, another
	// also finds.
	Marginal []MarginalContribution

	// UnionRecall is what you'd get running every scanner and ORing
	// results: |caught by ≥1| / |all valid|. BestSingleRecall is
	// max over scanners of that scanner's individual recall. The gap
	// between them is the case for running more than one tool.
	UnionRecall      float64
	BestSingleRecall float64
	BestSingleName   string

	// UnionFPCeiling is the sum of per-scanner FP counts. The real
	// union FP is ≤ this: if two scanners flag the same non-vuln
	// line, a human only triages it once. But benchmrk doesn't do
	// finding-to-finding matching across scanners, so we can only
	// show the upper bound. In practice the overlap is small
	// (different rule engines trip on different patterns), so the
	// ceiling is close.
	UnionFPCeiling int

	// Flaky = caught in some iterations but not all. The coverage
	// accounting above treats caught-once-of-N as caught (generous),
	// but flaky coverage is the first thing to distrust when two
	// compare runs disagree.
	Flaky []FlakyCoverage

	validTotal int // denominator for recall
}

// VulnCoverage records which scanners (by index) caught one vuln.
type VulnCoverage struct {
	Vuln     store.Vulnerability
	CaughtBy []int // indices into CoverageOverlap.ScannerNames
}

// MarginalContribution is what dropping one scanner costs.
type MarginalContribution struct {
	ScannerName string
	// Uniquely caught by this scanner, nobody else. The case for
	// keeping it. Sorted by criticality (must → should → may) so the
	// first entry is the strongest argument.
	Unique []store.Vulnerability
}

// FlakyCoverage flags a vuln a scanner catches inconsistently.
type FlakyCoverage struct {
	ScannerName string
	Vuln        store.Vulnerability
	HitRuns     int // caught in this many iterations…
	TotalRuns   int // …out of this many
}

// TierBreakdown counts vulns by criticality. Used for rendering
// "[must:1 should:2]" summaries without the caller iterating.
type TierBreakdown struct {
	Must, Should, May int
}

func TierCount(vulns []store.Vulnerability) TierBreakdown {
	var t TierBreakdown
	for _, v := range vulns {
		switch v.Criticality {
		case "must":
			t.Must++
		case "should":
			t.Should++
		case "may":
			t.May++
		}
	}
	return t
}

// ComputeCoverage builds the overlap picture for N scanners on one
// project. It assumes CompareScanners has already run (so MatchRun has
// fired for every run and finding_matches is populated) — calling this
// on unscored runs will report everything as caught-by-none.
//
// Multi-iteration handling: a scanner "catches" a vuln if ANY of its
// completed runs satisfied it. This is the generous interpretation —
// it answers "could this scanner find it" rather than "does it
// reliably find it". The Flaky list surfaces the difference.
func (s *Service) ComputeCoverage(ctx context.Context, scannerIDs []int64, projectID int64) (*CoverageOverlap, error) {
	if len(scannerIDs) < 2 {
		return nil, fmt.Errorf("coverage overlap needs ≥2 scanners, got %d", len(scannerIDs))
	}

	// Universe: valid vulnerabilities only. Invalid decoys are about
	// precision, not coverage — "both scanners fell for the same
	// decoy" isn't redundancy, it's a shared weakness, and belongs
	// in a different table.
	all, err := s.store.ListVulnerabilitiesByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list vulnerabilities: %w", err)
	}
	vulnByID := map[int64]store.Vulnerability{}
	for _, v := range all {
		if store.AnnotationStatus(v.Status) == store.AnnotationStatusValid {
			vulnByID[v.ID] = v
		}
	}

	cov := &CoverageOverlap{
		ScannerNames: make([]string, len(scannerIDs)),
		Marginal:     make([]MarginalContribution, len(scannerIDs)),
		validTotal:   len(vulnByID),
	}

	// caught[vulnID] is a set of scanner indices. hitRuns[i][vulnID]
	// counts iterations that scanner i caught this vuln in, for flaky
	// detection.
	caught := map[int64]map[int]bool{}
	hitRuns := make([]map[int64]int, len(scannerIDs))
	totalRuns := make([]int, len(scannerIDs))
	perScannerFP := make([]int, len(scannerIDs))

	for i, sid := range scannerIDs {
		scanner, err := s.store.GetScanner(ctx, sid)
		if err != nil {
			return nil, fmt.Errorf("get scanner %d: %w", sid, err)
		}
		cov.ScannerNames[i] = scanner.Name
		cov.Marginal[i].ScannerName = scanner.Name
		hitRuns[i] = map[int64]int{}

		runs, err := s.findRunsByScanner(ctx, sid, projectID)
		if err != nil {
			return nil, fmt.Errorf("find runs for scanner %s: %w", scanner.Name, err)
		}
		if len(runs) == 0 {
			return nil, fmt.Errorf("no completed runs for scanner %s", scanner.Name)
		}
		totalRuns[i] = len(runs)

		// Per-run: which vulns did this iteration catch? Union across
		// iterations, count per-iteration hits for flaky detection,
		// and accumulate FP (unmatched findings) for the union ceiling.
		for _, r := range runs {
			sat, err := s.store.ListSatisfiedVulns(ctx, r.ID, projectID)
			if err != nil {
				return nil, fmt.Errorf("satisfied vulns for run %d: %w", r.ID, err)
			}
			for _, v := range sat {
				if _, valid := vulnByID[v.ID]; !valid {
					continue // matched an invalid decoy — FP, not coverage
				}
				if caught[v.ID] == nil {
					caught[v.ID] = map[int]bool{}
				}
				caught[v.ID][i] = true
				hitRuns[i][v.ID]++
			}

			unmatched, err := s.store.ListUnmatchedFindings(ctx, r.ID)
			if err != nil {
				return nil, fmt.Errorf("unmatched findings for run %d: %w", r.ID, err)
			}
			perScannerFP[i] += len(unmatched)
		}
		// Average FP across iterations. Summing raw would make a
		// 4-iteration scanner look 4× noisier than a 1-iteration one.
		perScannerFP[i] /= len(runs)
	}

	// Partition and compute.
	nScanners := len(scannerIDs)
	perScannerCaught := make([]int, nScanners) // for best-single recall

	for vid, v := range vulnByID {
		hitters, any := caught[vid]
		if !any {
			cov.CaughtByNone = append(cov.CaughtByNone, v)
			continue
		}
		for i := range hitters {
			perScannerCaught[i]++
		}
		switch len(hitters) {
		case nScanners:
			cov.CaughtByAll = append(cov.CaughtByAll, v)
		case 1:
			// Exactly one catcher → that scanner's marginal contribution.
			// Also lands in CaughtBySome so the middle partition is
			// exhaustive.
			for only := range hitters {
				cov.Marginal[only].Unique = append(cov.Marginal[only].Unique, v)
			}
			fallthrough
		default:
			idx := make([]int, 0, len(hitters))
			for i := range hitters {
				idx = append(idx, i)
			}
			sort.Ints(idx)
			cov.CaughtBySome = append(cov.CaughtBySome, VulnCoverage{Vuln: v, CaughtBy: idx})
		}
	}

	// Flaky detection: a scanner caught this vuln in at least one run
	// but not every run. Only surfaces when iterations > 1 — a
	// single-iteration scanner can't be observed flaking.
	for i := range scannerIDs {
		if totalRuns[i] < 2 {
			continue
		}
		for vid, hits := range hitRuns[i] {
			if hits > 0 && hits < totalRuns[i] {
				cov.Flaky = append(cov.Flaky, FlakyCoverage{
					ScannerName: cov.ScannerNames[i],
					Vuln:        vulnByID[vid],
					HitRuns:     hits,
					TotalRuns:   totalRuns[i],
				})
			}
		}
	}

	// Aggregates.
	if cov.validTotal > 0 {
		cov.UnionRecall = float64(len(vulnByID)-len(cov.CaughtByNone)) / float64(cov.validTotal)
		for i, n := range perScannerCaught {
			r := float64(n) / float64(cov.validTotal)
			if r > cov.BestSingleRecall {
				cov.BestSingleRecall = r
				cov.BestSingleName = cov.ScannerNames[i]
			}
		}
	}
	for _, fp := range perScannerFP {
		cov.UnionFPCeiling += fp
	}

	// Deterministic output. Map iteration order varies run-to-run;
	// without this two invocations print the same facts in different
	// orders, which looks like nondeterminism in the analysis.
	sortVulnsByTierThenName(cov.CaughtByAll)
	sortVulnsByTierThenName(cov.CaughtByNone)
	for i := range cov.Marginal {
		sortVulnsByTierThenName(cov.Marginal[i].Unique)
	}
	sort.Slice(cov.CaughtBySome, func(i, j int) bool {
		return cov.CaughtBySome[i].Vuln.Name < cov.CaughtBySome[j].Vuln.Name
	})
	sort.Slice(cov.Flaky, func(i, j int) bool {
		if cov.Flaky[i].ScannerName != cov.Flaky[j].ScannerName {
			return cov.Flaky[i].ScannerName < cov.Flaky[j].ScannerName
		}
		return cov.Flaky[i].Vuln.Name < cov.Flaky[j].Vuln.Name
	})

	return cov, nil
}

// tierRank orders criticality for sorting. Lower = more important.
// Unknown tiers sort last so a typo in an annotation file doesn't
// promote a should-tier vuln above a must.
func tierRank(criticality string) int {
	switch criticality {
	case "must":
		return 0
	case "should":
		return 1
	case "may":
		return 2
	default:
		return 3
	}
}

func sortVulnsByTierThenName(vs []store.Vulnerability) {
	sort.Slice(vs, func(i, j int) bool {
		ri, rj := tierRank(vs[i].Criticality), tierRank(vs[j].Criticality)
		if ri != rj {
			return ri < rj
		}
		return vs[i].Name < vs[j].Name
	})
}
