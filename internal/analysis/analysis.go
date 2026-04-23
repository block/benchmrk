package analysis

import (
	"context"
	"fmt"

	"github.com/block/benchmrk/internal/store"
)

// Store defines the store methods needed by the analysis service.
type Store interface {
	GetRun(ctx context.Context, id int64) (*store.Run, error)
	GetAnnotation(ctx context.Context, id int64) (*store.Annotation, error)
	GetFinding(ctx context.Context, id int64) (*store.Finding, error)
	ListFindingsByRun(ctx context.Context, runID int64) ([]store.Finding, error)
	ListFindingMatchesByRun(ctx context.Context, runID int64) ([]store.FindingMatch, error)
	ListUnmatchedFindings(ctx context.Context, runID int64) ([]store.Finding, error)
	ListUnmatchedAnnotations(ctx context.Context, runID, projectID int64) ([]store.Annotation, error)
	ListAnnotationsByProject(ctx context.Context, projectID int64) ([]store.Annotation, error)
	ListRunsByExperiment(ctx context.Context, experimentID int64) ([]store.Run, error)
	GetExperiment(ctx context.Context, id int64) (*store.Experiment, error)
	ListExperimentScanners(ctx context.Context, experimentID int64) ([]store.Scanner, error)
	ListExperimentProjects(ctx context.Context, experimentID int64) ([]store.CorpusProject, error)
	GetScanner(ctx context.Context, id int64) (*store.Scanner, error)
	GetProject(ctx context.Context, id int64) (*store.CorpusProject, error)
	ListRunsByScannerProject(ctx context.Context, scannerID, projectID int64) ([]store.Run, error)
	CreateFindingMatch(ctx context.Context, m *store.FindingMatch) (int64, error)
	ListDispositionsByRun(ctx context.Context, runID int64) ([]store.FindingDisposition, error)
	CreateAnnotation(ctx context.Context, a *store.Annotation) (int64, error)
	ListAllGroupMembersByProject(ctx context.Context, projectID int64) ([]store.AnnotationGroupMember, error)
	StampRunScorer(ctx context.Context, runID int64, matcherVersion, annotationHash string) error
	// Vulnerability-level queries for ComputeVulnMetrics. The per-
	// annotation path above stays for reports and detail views; these
	// are what compare uses.
	ListVulnerabilitiesByProject(ctx context.Context, projectID int64) ([]store.Vulnerability, error)
	ListSatisfiedVulns(ctx context.Context, runID, projectID int64) ([]store.Vulnerability, error)
	ListUnsatisfiedVulns(ctx context.Context, runID, projectID int64) ([]store.Vulnerability, error)
	ListVulnCWEs(ctx context.Context, projectID int64) (map[int64][]string, error)
	ListEvidenceByProject(ctx context.Context, projectID int64) ([]store.Evidence, error)
	VulnConsensus(ctx context.Context, projectID int64) (map[int64]int, error)
}

// Service provides analysis functionality for runs and experiments.
type Service struct {
	store   Store
	matcher *Matcher

	// MinConsensus filters vulnerabilities to those annotated by at
	// least this many people before computing metrics. 0 = no filter.
	// Set from the CLI's --min-consensus flag before calling
	// CompareScanners. Applies only to AnalyzeRun (the vuln-level
	// path); the per-annotation detail views ignore it.
	//
	// Use case: check whether your F1 is riding on single-annotator
	// calls. Run compare once unfiltered, once at --min-consensus 2,
	// and see how much the ranking moves.
	MinConsensus int
}

// NewService creates an analysis service with the given store and matcher.
func NewService(s Store, m *Matcher) *Service {
	if m == nil {
		m = NewMatcher()
	}
	return &Service{
		store:   s,
		matcher: m,
	}
}

// MatchRun runs the matcher for a run, persisting any new matches to the database.
// It is idempotent: existing matches are preserved and the matcher only processes
// findings that don't already have a match.
func (s *Service) MatchRun(ctx context.Context, runID int64) error {
	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("get run: %w", err)
	}

	// Check if matches already exist for this run
	existingMatches, err := s.store.ListFindingMatchesByRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("list existing matches: %w", err)
	}
	if len(existingMatches) > 0 {
		return nil // already matched
	}

	findings, err := s.store.ListFindingsByRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}

	annotations, err := s.store.ListAnnotationsByProject(ctx, run.ProjectID)
	if err != nil {
		return fmt.Errorf("list annotations: %w", err)
	}

	// Stamp the scorer before matching. If the stamp fails we abort —
	// writing matches without recording which matcher produced them is
	// exactly the unattributable-scoring problem the stamp exists to
	// prevent. The idempotence check above (bail if matches exist) means
	// re-scoring after DELETE FROM finding_matches re-stamps correctly.
	hash, err := s.annotationHash(ctx, run.ProjectID)
	if err != nil {
		return fmt.Errorf("hash annotations: %w", err)
	}
	if err := s.store.StampRunScorer(ctx, runID, MatcherVersion, hash); err != nil {
		return fmt.Errorf("stamp scorer: %w", err)
	}

	// Load the full CWE sets so matchScore can check a finding's CWE
	// against every acceptable CWE for the vuln, not just the one the
	// compat shim's Annotation.CWEID surfaces. evidence→vuln→CWEs.
	cweStrings, err := s.store.ListVulnCWEs(ctx, run.ProjectID)
	if err != nil {
		return fmt.Errorf("list vuln cwes: %w", err)
	}
	evidence, err := s.store.ListEvidenceByProject(ctx, run.ProjectID)
	if err != nil {
		return fmt.Errorf("list evidence: %w", err)
	}
	cweSets := buildCWESets(evidence, cweStrings)

	matches, err := s.matcher.Match(findings, annotations, cweSets)
	if err != nil {
		return fmt.Errorf("match findings: %w", err)
	}

	// Propagate group satisfaction into persisted rows. Without this, group
	// rescue only happens at ComputeMetrics time and leaves no trace in
	// finding_matches — "why did this score TP?" has no answer in the DB.
	// With it, rescued annotations get a match_type='group' row pointing at
	// the finding that satisfied their group.
	groups, err := s.loadGroupsMap(ctx, run.ProjectID)
	if err != nil {
		return fmt.Errorf("load groups: %w", err)
	}
	matches = append(matches, s.matcher.PropagateGroups(matches, groups)...)

	for i := range matches {
		if _, err := s.store.CreateFindingMatch(ctx, &matches[i]); err != nil {
			return fmt.Errorf("create finding match: %w", err)
		}
	}

	return nil
}

// AnalyzeRun computes vulnerability-level metrics for a single run.
//
// This is the post-010 counting: one satisfied vulnerability = one TP
// regardless of how many evidence locations matched. The per-annotation
// path (AnalyzeRunWithCategories, AnalyzeRunDetail) still exists for
// reports and detail views that want location-level breakdown, but
// compare uses this.
func (s *Service) AnalyzeRun(ctx context.Context, runID int64) (*Metrics, error) {
	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("get run: %w", err)
	}

	if err := s.MatchRun(ctx, runID); err != nil {
		return nil, fmt.Errorf("match run: %w", err)
	}

	satisfied, err := s.store.ListSatisfiedVulns(ctx, runID, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list satisfied vulns: %w", err)
	}
	unsatisfied, err := s.store.ListUnsatisfiedVulns(ctx, runID, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list unsatisfied vulns: %w", err)
	}

	// Consensus filter: drop vulns annotated by fewer than MinConsensus
	// people from BOTH lists. They contribute to neither TP nor FN —
	// they simply don't exist for this comparison. Unmatched findings
	// (FPs) are unaffected; findings don't have consensus.
	if s.MinConsensus > 0 {
		consensus, err := s.store.VulnConsensus(ctx, run.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("load consensus: %w", err)
		}
		keep := func(vs []store.Vulnerability) []store.Vulnerability {
			out := vs[:0]
			for _, v := range vs {
				if consensus[v.ID] >= s.MinConsensus {
					out = append(out, v)
				}
			}
			return out
		}
		satisfied = keep(satisfied)
		unsatisfied = keep(unsatisfied)
	}
	unmatched, err := s.store.ListUnmatchedFindings(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list unmatched findings: %w", err)
	}
	disp, err := s.loadDispositionMap(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("load dispositions: %w", err)
	}

	m := ComputeVulnMetrics(satisfied, unsatisfied, unmatched, disp)

	if run.DurationMs.Valid {
		m.DurationMs = run.DurationMs.Int64
	}
	if run.MemoryPeakBytes.Valid {
		m.MemoryPeakBytes = run.MemoryPeakBytes.Int64
	}
	return m, nil
}

// AnalyzeRunWithCategories computes both overall and per-category metrics for a run.
func (s *Service) AnalyzeRunWithCategories(ctx context.Context, runID int64) (*Metrics, map[string]*CategoryMetrics, error) {
	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return nil, nil, fmt.Errorf("get run: %w", err)
	}

	// Ensure matches are computed and persisted
	if err := s.MatchRun(ctx, runID); err != nil {
		return nil, nil, fmt.Errorf("match run: %w", err)
	}

	matches, err := s.store.ListFindingMatchesByRun(ctx, runID)
	if err != nil {
		return nil, nil, fmt.Errorf("list finding matches: %w", err)
	}

	unmatchedFindings, err := s.store.ListUnmatchedFindings(ctx, runID)
	if err != nil {
		return nil, nil, fmt.Errorf("list unmatched findings: %w", err)
	}

	unmatchedAnnotations, err := s.store.ListUnmatchedAnnotations(ctx, runID, run.ProjectID)
	if err != nil {
		return nil, nil, fmt.Errorf("list unmatched annotations: %w", err)
	}

	matchesWithAnnotations, err := s.buildMatchesWithAnnotations(ctx, matches)
	if err != nil {
		return nil, nil, fmt.Errorf("build matches with annotations: %w", err)
	}

	dispMap, err := s.loadDispositionMap(ctx, runID)
	if err != nil {
		return nil, nil, fmt.Errorf("load dispositions: %w", err)
	}

	metrics := ComputeMetrics(matchesWithAnnotations, unmatchedFindings, unmatchedAnnotations, dispMap)
	categoryMetrics := ComputeCategoryMetrics(matchesWithAnnotations, unmatchedFindings, unmatchedAnnotations, dispMap)

	if run.DurationMs.Valid {
		metrics.DurationMs = run.DurationMs.Int64
	}
	if run.MemoryPeakBytes.Valid {
		metrics.MemoryPeakBytes = run.MemoryPeakBytes.Int64
	}

	return metrics, categoryMetrics, nil
}

// AnalyzeRunDetail computes full detail for a run, including per-annotation and per-finding results.
func (s *Service) AnalyzeRunDetail(ctx context.Context, runID int64) (*RunDetail, error) {
	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("get run: %w", err)
	}

	// Ensure matches are computed and persisted
	if err := s.MatchRun(ctx, runID); err != nil {
		return nil, fmt.Errorf("match run: %w", err)
	}

	matches, err := s.store.ListFindingMatchesByRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list finding matches: %w", err)
	}

	unmatchedFindings, err := s.store.ListUnmatchedFindings(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list unmatched findings: %w", err)
	}

	unmatchedAnnotations, err := s.store.ListUnmatchedAnnotations(ctx, runID, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list unmatched annotations: %w", err)
	}

	allFindings, err := s.store.ListFindingsByRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list findings by run: %w", err)
	}

	allAnnotations, err := s.store.ListAnnotationsByProject(ctx, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list annotations by project: %w", err)
	}

	matchesWithAnnotations, err := s.buildMatchesWithAnnotations(ctx, matches)
	if err != nil {
		return nil, fmt.Errorf("build matches with annotations: %w", err)
	}

	dispMap, err := s.loadDispositionMap(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("load dispositions: %w", err)
	}

	metrics := ComputeMetrics(matchesWithAnnotations, unmatchedFindings, unmatchedAnnotations, dispMap)
	categoryMetrics := ComputeCategoryMetrics(matchesWithAnnotations, unmatchedFindings, unmatchedAnnotations, dispMap)

	if run.DurationMs.Valid {
		metrics.DurationMs = run.DurationMs.Int64
	}
	if run.MemoryPeakBytes.Valid {
		metrics.MemoryPeakBytes = run.MemoryPeakBytes.Int64
	}

	// Build a map of findings by ID for quick lookup
	findingsByID := make(map[int64]store.Finding, len(allFindings))
	for _, f := range allFindings {
		findingsByID[f.ID] = f
	}

	// Build indexes from matches: annotation ID → match info, finding ID → match info
	type matchInfo struct {
		match      store.FindingMatch
		annotation store.Annotation
	}
	matchByAnnotationID := make(map[int64]matchInfo, len(matchesWithAnnotations))
	matchByFindingID := make(map[int64]matchInfo, len(matchesWithAnnotations))
	for _, mwa := range matchesWithAnnotations {
		info := matchInfo{match: mwa.Match, annotation: mwa.Annotation}
		matchByAnnotationID[mwa.Match.AnnotationID] = info
		matchByFindingID[mwa.Match.FindingID] = info
	}

	// Build AnnotationResults
	annotationResults := make([]AnnotationResult, 0, len(allAnnotations))
	for _, ann := range allAnnotations {
		ar := AnnotationResult{
			Annotation: ann,
		}
		if info, ok := matchByAnnotationID[ann.ID]; ok {
			ar.Matched = true
			ar.MatchType = info.match.MatchType
			if info.match.Confidence.Valid {
				ar.Confidence = info.match.Confidence.Float64
			}
			if f, fOK := findingsByID[info.match.FindingID]; fOK {
				fCopy := f
				ar.MatchedFinding = &fCopy
			}
			if IsPositiveAnnotation(ann.Status) {
				ar.Classification = "TP"
			} else if IsNegativeAnnotation(ann.Status) {
				ar.Classification = "FP"
			}
		} else {
			// Group-rescued annotations never reach here — PropagateGroups
			// gave them a match_type='group' row, so they hit the ok
			// branch above with MatchType="group", Classification="TP".
			if IsPositiveAnnotation(ann.Status) {
				ar.Classification = "FN"
			} else if IsNegativeAnnotation(ann.Status) {
				ar.Classification = "TN"
			}
		}
		annotationResults = append(annotationResults, ar)
	}

	// Build FindingResults
	findingResults := make([]FindingResult, 0, len(allFindings))
	for _, f := range allFindings {
		fr := FindingResult{
			Finding: f,
		}
		if info, ok := matchByFindingID[f.ID]; ok {
			fr.Matched = true
			fr.MatchType = info.match.MatchType
			if info.match.Confidence.Valid {
				fr.Confidence = info.match.Confidence.Float64
			}
			annCopy := info.annotation
			fr.MatchedAnnotation = &annCopy
			if IsPositiveAnnotation(info.annotation.Status) {
				fr.Classification = "TP"
			} else {
				fr.Classification = "FP"
			}
		} else {
			// Unmatched finding - check disposition
			if d, ok := dispMap[f.ID]; ok {
				fr.Disposition = d.Disposition
				if d.Disposition == store.DispositionTP {
					fr.Classification = "TP"
				} else {
					fr.Classification = "FP"
				}
			} else {
				fr.Classification = "FP"
			}
		}
		findingResults = append(findingResults, fr)
	}

	return &RunDetail{
		Metrics:           metrics,
		CategoryMetrics:   categoryMetrics,
		AnnotationResults: annotationResults,
		FindingResults:    findingResults,
	}, nil
}

// AnalyzeExperiment computes metrics for all runs in an experiment, grouped by scanner and project.
// When multiple iterations exist for a scanner×project combination, metrics are averaged.
// Returns map[scannerName]map[projectName]*Metrics.
func (s *Service) AnalyzeExperiment(ctx context.Context, experimentID int64) (map[string]map[string]*Metrics, error) {
	runs, err := s.store.ListRunsByExperiment(ctx, experimentID)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}

	scannerNames := make(map[int64]string)
	projectNames := make(map[int64]string)

	// Collect all metrics per scanner×project, keyed by "scannerID:projectID".
	type spKey struct{ scannerID, projectID int64 }
	collected := make(map[spKey][]*Metrics)

	for _, run := range runs {
		if run.Status != store.RunStatusCompleted {
			continue
		}

		if _, ok := scannerNames[run.ScannerID]; !ok {
			scanner, err := s.store.GetScanner(ctx, run.ScannerID)
			if err != nil {
				return nil, fmt.Errorf("get scanner %d: %w", run.ScannerID, err)
			}
			scannerNames[run.ScannerID] = scanner.Name
		}

		if _, ok := projectNames[run.ProjectID]; !ok {
			project, err := s.store.GetProject(ctx, run.ProjectID)
			if err != nil {
				return nil, fmt.Errorf("get project %d: %w", run.ProjectID, err)
			}
			projectNames[run.ProjectID] = project.Name
		}

		metrics, err := s.AnalyzeRun(ctx, run.ID)
		if err != nil {
			return nil, fmt.Errorf("analyze run %d: %w", run.ID, err)
		}

		key := spKey{run.ScannerID, run.ProjectID}
		collected[key] = append(collected[key], metrics)
	}

	// Average metrics across iterations for each scanner×project.
	result := make(map[string]map[string]*Metrics)
	for key, metricsList := range collected {
		scannerName := scannerNames[key.scannerID]
		projectName := projectNames[key.projectID]
		if result[scannerName] == nil {
			result[scannerName] = make(map[string]*Metrics)
		}
		result[scannerName][projectName] = AverageMetrics(metricsList)
	}

	return result, nil
}

// ScannerComparisonEntry holds one scanner's metrics and its delta vs the baseline.
type ScannerComparisonEntry struct {
	ScannerName    string
	ScannerID      int64
	ScannerVersion string
	Metrics        *Metrics
	Delta          *MetricsDelta // nil for the baseline scanner
	RunID          int64

	// Iterations is the number of runs aggregated into Metrics. 1 means
	// a single run — the ±σ in Aggregated is 0 by definition and the
	// compare output suppresses it. >1 means Metrics is the mean and
	// Aggregated carries the spread.
	Iterations int

	// Aggregated carries mean/median/σ across iterations. Always
	// populated (even for Iterations==1) so callers don't have to
	// nil-check; the σ fields are just 0 when there's nothing to spread.
	Aggregated *AggregatedMetrics
}

// MetricsDelta contains the difference in metrics relative to a baseline scanner.
type MetricsDelta struct {
	Precision       float64
	Recall          float64
	F1              float64
	Accuracy        float64
	DurationDeltaMs int64
}

// MultiComparison holds a comparison of N scanners on a project.
type MultiComparison struct {
	ProjectName   string
	ProjectID     int64
	BaselineIndex int // index into Entries for the baseline scanner
	Entries       []ScannerComparisonEntry

	// Scorer records whether all runs in this comparison agree on
	// matcher version and annotation hash. When !Clean(), the BEST
	// column is comparing numbers produced by different scorers and
	// should be treated as advisory only.
	Scorer ScorerMismatch
}

// AnnotationResult describes how a single annotation was handled during a run.
type AnnotationResult struct {
	Annotation     store.Annotation
	Matched        bool           // true if a finding matched this annotation
	MatchType      string         // "exact", "fuzzy", "category", or "" if unmatched
	Confidence     float64        // match confidence, 0 if unmatched
	MatchedFinding *store.Finding // the finding that matched, nil if unmatched
	Classification string         // "TP", "FP", "TN", "FN"
}

// FindingResult describes how a single finding was classified during a run.
type FindingResult struct {
	Finding           store.Finding
	Matched           bool   // true if matched to an annotation
	MatchType         string // "exact", "fuzzy", "category", or "" if unmatched
	Confidence        float64
	MatchedAnnotation *store.Annotation // nil if unmatched
	Classification    string            // "TP", "FP"
	Disposition       store.Disposition // "tp", "fp", "needs_review", or "" if no disposition
}

// RunDetail contains full analysis detail for a run, including per-annotation and per-finding breakdown.
type RunDetail struct {
	Metrics           *Metrics
	CategoryMetrics   map[string]*CategoryMetrics
	AnnotationResults []AnnotationResult
	FindingResults    []FindingResult
}

// CompareScanners compares N scanners' performance on a given project.
// The first scanner in scannerIDs is used as the baseline.
func (s *Service) CompareScanners(ctx context.Context, scannerIDs []int64, projectID int64) (*MultiComparison, error) {
	if len(scannerIDs) < 2 {
		return nil, fmt.Errorf("at least 2 scanner IDs required, got %d", len(scannerIDs))
	}

	project, err := s.store.GetProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	// Collect scorer stamps across every run we touch. When all runs agree,
	// these maps each have one key and the comparison is clean. When they
	// don't, the caller can see which runs belong to which scorer and
	// decide whether the comparison is meaningful anyway.
	scorer := ScorerMismatch{
		MatcherVersions:  map[string][]int64{},
		AnnotationHashes: map[string][]int64{},
	}

	entries := make([]ScannerComparisonEntry, 0, len(scannerIDs))
	for _, sid := range scannerIDs {
		scanner, err := s.store.GetScanner(ctx, sid)
		if err != nil {
			return nil, fmt.Errorf("get scanner %d: %w", sid, err)
		}
		runs, err := s.findRunsByScanner(ctx, sid, projectID)
		if err != nil {
			return nil, fmt.Errorf("find runs for scanner %s: %w", scanner.Name, err)
		}
		if len(runs) == 0 {
			return nil, fmt.Errorf("no completed runs for scanner %s on project %s", scanner.Name, project.Name)
		}

		// Analyze all iterations. AnalyzeRun calls MatchRun which stamps the
		// scorer on any run that doesn't have matches yet — so by the time we
		// read r.MatcherVersion below it's either the freshly-stamped current
		// value or whatever was stamped when the run was last scored.
		// One subtlety: MatchRun bails early when matches exist, which means
		// the stamp reflects the LAST scoring, not the current MatcherVersion.
		// That's correct — the matches in the DB were produced by that scorer,
		// and those matches are what ComputeMetrics is about to read.
		allMetrics := make([]*Metrics, 0, len(runs))
		runMetrics := make([]RunMetrics, 0, len(runs))
		for _, r := range runs {
			m, err := s.AnalyzeRun(ctx, r.ID)
			if err != nil {
				return nil, fmt.Errorf("analyze run for scanner %s: %w", scanner.Name, err)
			}
			allMetrics = append(allMetrics, m)
			runMetrics = append(runMetrics, RunMetrics{Metrics: *m, RunID: r.ID, Iteration: r.Iteration})

			// Re-fetch: AnalyzeRun → MatchRun may have just stamped this row.
			// The r in our slice is a pre-stamp snapshot.
			stamped, err := s.store.GetRun(ctx, r.ID)
			if err != nil {
				return nil, fmt.Errorf("re-fetch run %d: %w", r.ID, err)
			}
			mv := stamped.MatcherVersion.String // "" for NULL (pre-009 runs)
			ah := stamped.AnnotationHash.String
			scorer.MatcherVersions[mv] = append(scorer.MatcherVersions[mv], r.ID)
			scorer.AnnotationHashes[ah] = append(scorer.AnnotationHashes[ah], r.ID)
		}

		entries = append(entries, ScannerComparisonEntry{
			ScannerName:    scanner.Name,
			ScannerID:      scanner.ID,
			ScannerVersion: scanner.Version,
			Metrics:        AverageMetrics(allMetrics),
			Iterations:     len(runs),
			Aggregated:     AggregateRunMetrics(runMetrics),
			RunID:          runs[0].ID,
		})
	}

	// Compute deltas vs baseline (entries[0])
	baseline := entries[0].Metrics
	for i := 1; i < len(entries); i++ {
		m := entries[i].Metrics
		entries[i].Delta = &MetricsDelta{
			Precision:       m.Precision - baseline.Precision,
			Recall:          m.Recall - baseline.Recall,
			F1:              m.F1 - baseline.F1,
			Accuracy:        m.Accuracy - baseline.Accuracy,
			DurationDeltaMs: m.DurationMs - baseline.DurationMs,
		}
	}

	return &MultiComparison{
		ProjectName:   project.Name,
		ProjectID:     project.ID,
		BaselineIndex: 0,
		Entries:       entries,
		Scorer:        scorer,
	}, nil
}

// loadGroupsMap loads annotation group memberships for a project and returns
// a map of annotationID → []groupID for use with PropagateGroups.
func (s *Service) loadGroupsMap(ctx context.Context, projectID int64) (map[int64][]int64, error) {
	members, err := s.store.ListAllGroupMembersByProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	if len(members) == 0 {
		return nil, nil
	}
	groups := make(map[int64][]int64)
	for _, m := range members {
		groups[m.AnnotationID] = append(groups[m.AnnotationID], m.GroupID)
	}
	return groups, nil
}

// loadDispositionMap loads finding dispositions for a run and returns them keyed by finding ID.
func (s *Service) loadDispositionMap(ctx context.Context, runID int64) (map[int64]store.FindingDisposition, error) {
	dispositions, err := s.store.ListDispositionsByRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list dispositions: %w", err)
	}
	dispMap := make(map[int64]store.FindingDisposition, len(dispositions))
	for _, d := range dispositions {
		dispMap[d.FindingID] = d
	}
	return dispMap, nil
}

// buildMatchesWithAnnotations loads annotations for each match.
func (s *Service) buildMatchesWithAnnotations(ctx context.Context, matches []store.FindingMatch) ([]MatchWithAnnotation, error) {
	result := make([]MatchWithAnnotation, 0, len(matches))
	for _, m := range matches {
		annotation, err := s.store.GetAnnotation(ctx, m.AnnotationID)
		if err != nil {
			return nil, fmt.Errorf("get annotation %d: %w", m.AnnotationID, err)
		}
		result = append(result, MatchWithAnnotation{
			Match:      m,
			Annotation: *annotation,
		})
	}
	return result, nil
}

// findRunsByScanner finds completed runs for a scanner on a project.
func (s *Service) findRunsByScanner(ctx context.Context, scannerID, projectID int64) ([]store.Run, error) {
	runs, err := s.store.ListRunsByScannerProject(ctx, scannerID, projectID)
	if err != nil {
		return nil, err
	}
	// Filter to only completed runs
	completed := make([]store.Run, 0, len(runs))
	for _, r := range runs {
		if r.Status == store.RunStatusCompleted {
			completed = append(completed, r)
		}
	}
	return completed, nil
}
