package analysis

import (
	"context"

	"github.com/block/benchmrk/internal/analysis/cwe"
	"github.com/block/benchmrk/internal/store"
)

// MatcherVersion identifies the matching semantics that produced a run's
// finding_matches rows. Bump it whenever matcher.go, cwe/, or anything else
// that changes how findings map to annotations is modified. Two F1 numbers
// are comparable iff their runs share this value.
//
// History:
//
//	"1"  — implicit pre-009 value. String-equality CWE matching, ResolveGroups
//	       at metrics time only. Never stamped (the column didn't exist).
//	"2"  — MITRE-hierarchy CWE matching (internal/analysis/cwe), persisted
//	       group propagation, deterministic wide-range tiebreak. The
//	       hierarchy tier and the startGap tiebreak both change which
//	       finding wins the greedy assignment, so runs scored under "1"
//	       and "2" assign the same findings to different annotations.
//	"3"  — vulnerability-level TP accounting (migration 010). A vuln with
//	       N evidence locations, one matched, scores 1 TP instead of N.
//	       Matcher also now checks finding-CWE against the vuln's full
//	       acceptable-CWE set instead of whichever single CWE the compat
//	       shim surfaced. Both changes move numbers; the accounting change
//	       is the big one.
//
// Keep this a hand-bumped string. A build-time hash of the matcher source
// would be more "correct" but would bump on every comment edit and make
// the history line above impossible to maintain. The discipline of writing
// a history entry when you bump the number is the point.
const MatcherVersion = "3"

// annotationHash delegates to the store. Kept as a Service method so
// MatchRun's call site stays clean; the real implementation lives in
// store.AnnotationHash so corpus imports can record the same hash
// without depending on the analysis package.
func (s *Service) annotationHash(ctx context.Context, projectID int64) (string, error) {
	type hasher interface {
		AnnotationHash(ctx context.Context, projectID int64) (string, error)
	}
	// The concrete *store.Store has this method. Test mocks don't need
	// to — they return "" and the stamp is just less useful, not wrong.
	if h, ok := s.store.(hasher); ok {
		return h.AnnotationHash(ctx, projectID)
	}
	return "", nil
}

// ScorerMismatch describes runs in a comparison that were scored under
// different matcher versions or against different annotation sets. The
// comparison is still emitted — sometimes you want to see the numbers
// anyway — but the presence of a mismatch means the BEST column is
// comparing apples to oranges.
type ScorerMismatch struct {
	// MatcherVersions maps version → run IDs that used it. len > 1 means
	// the runs were scored by different matcher logic. An empty-string key
	// holds runs that predate version stamping.
	MatcherVersions map[string][]int64

	// AnnotationHashes maps hash → run IDs. len > 1 means the ground truth
	// changed between runs.
	AnnotationHashes map[string][]int64
}

// Clean reports whether every run agrees on both scorer fields.
func (m *ScorerMismatch) Clean() bool {
	return len(m.MatcherVersions) <= 1 && len(m.AnnotationHashes) <= 1
}

// buildCWESets inverts vuln→CWEs into evidence→CWEs (normalized to
// ints) so matchScore can check a finding against the full acceptable
// set keyed on the evidence row it's scoring against. Unparseable CWE
// strings are dropped — better a degraded match than a crash on a
// typo in an annotation file.
func buildCWESets(evidence []store.Evidence, cwesByVuln map[int64][]string) map[int64][]int {
	if len(cwesByVuln) == 0 {
		return nil
	}
	// Normalize once per vuln, not once per evidence row.
	normalized := make(map[int64][]int, len(cwesByVuln))
	for vid, strs := range cwesByVuln {
		ints := make([]int, 0, len(strs))
		for _, s := range strs {
			if n, ok := cwe.Normalize(s); ok {
				ints = append(ints, n)
			}
		}
		if len(ints) > 0 {
			normalized[vid] = ints
		}
	}
	out := make(map[int64][]int, len(evidence))
	for _, e := range evidence {
		if set := normalized[e.VulnID]; len(set) > 0 {
			out[e.ID] = set
		}
	}
	return out
}
