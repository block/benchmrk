package analysis

import (
	"database/sql"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/block/benchmrk/internal/analysis/cwe"
	"github.com/block/benchmrk/internal/store"
)

// MatchType represents the type of match between a finding and annotation.
type MatchType string

const (
	MatchTypeExact     MatchType = "exact"
	MatchTypeHierarchy MatchType = "hierarchy"
	MatchTypeFuzzy     MatchType = "fuzzy"
	MatchTypeCategory  MatchType = "category"
	MatchTypeGroup     MatchType = "group"
	MatchTypeSameLine  MatchType = "same_line"
)

// Matcher matches scanner findings to ground-truth annotations using a tiered algorithm.
type Matcher struct {
	// FuzzyLineThreshold is the maximum line distance for fuzzy matching (default: 5)
	FuzzyLineThreshold int

	// CategoryLineThreshold is the maximum line distance for category matching (default: 20)
	CategoryLineThreshold int

	// FuzzyMinConfidence is the minimum confidence for fuzzy matches (default: 0.5)
	FuzzyMinConfidence float64

	// FuzzyMaxConfidence is the maximum confidence for fuzzy matches (default: 0.9)
	FuzzyMaxConfidence float64

	// CategoryMinConfidence is the minimum confidence for category matches (default: 0.3)
	CategoryMinConfidence float64

	// CategoryMaxConfidence is the maximum confidence for category matches (default: 0.5)
	CategoryMaxConfidence float64

	// GroupConfidence is the confidence for cross-file group matches (default: 0.4)
	GroupConfidence float64

	// SameLineConfidence is the confidence for same-line fallback matches
	// where the CWE categories differ (default: 0.2)
	SameLineConfidence float64

	// CWEMaxDepth bounds the MITRE-hierarchy walk for CWE relatedness.
	// Combined parent-chain hops; 3 reaches siblings-of-siblings and
	// stops before the upper tree where everything converges.
	// (default: 3)
	CWEMaxDepth int

	// HierarchyBaseConfidence is the confidence of a same-location match
	// where the CWEs are one hop apart in the hierarchy (parent/child or
	// curated pair). Each additional hop costs HierarchyDepthPenalty.
	// Default 0.95 puts a direct-parent hierarchy match just below an
	// exact string match (1.0) and well above the best fuzzy (0.9).
	HierarchyBaseConfidence float64

	// HierarchyDepthPenalty is subtracted per hop beyond 1.
	// Default 0.10: depth 1 → 0.95, depth 2 → 0.85, depth 3 → 0.75.
	// Depth-3 hierarchy still beats the best fuzzy (0.9 at zero line
	// distance) — wrong? No: hierarchy requires lineDistance==0, so it's
	// "definitely the same code, probably the same bug" vs fuzzy's
	// "nearby code, compatible bug." Tighter location wins.
	HierarchyDepthPenalty float64
}

// NewMatcher creates a Matcher with default thresholds.
func NewMatcher() *Matcher {
	return &Matcher{
		FuzzyLineThreshold:      5,
		CategoryLineThreshold:   20,
		FuzzyMinConfidence:      0.5,
		FuzzyMaxConfidence:      0.9,
		CategoryMinConfidence:   0.3,
		CategoryMaxConfidence:   0.5,
		GroupConfidence:         0.4,
		SameLineConfidence:      0.2,
		CWEMaxDepth:             3,
		HierarchyBaseConfidence: 0.95,
		HierarchyDepthPenalty:   0.10,
	}
}

// candidateMatch represents a potential match between a finding and annotation.
type candidateMatch struct {
	FindingIdx   int
	AnnotationID int64
	MatchType    MatchType
	Confidence   float64

	// startGap breaks confidence ties. A finding whose range spans many
	// annotations (e.g. a consolidated IDOR reported at lines 88-166 that
	// overlaps annotations at 88, 125, and 140) scores exact/1.0 against
	// all of them — rangeDistance is 0 for each. The greedy pass then
	// picks whichever the sort puts first, which was nondeterministic
	// under sort.Slice. startGap = |f.StartLine - a.StartLine| lets the
	// tiebreak favour the annotation whose anchor is closest to the
	// finding's anchor, which is what a human reviewer would pick.
	startGap int
}

// Match matches findings to annotations using a tiered algorithm:
//  1. Exact:     overlapping lines, identical CWE ID → confidence 1.0
//  2. Hierarchy: overlapping lines, CWE IDs related in the MITRE tree
//     (parent/child, shared non-pillar ancestor, shared category, or
//     curated pair) → confidence 0.75–0.95 by hierarchy distance
//  3. Fuzzy:     lines within FuzzyLineThreshold, CWE-related → 0.5–0.9
//  4. Category:  lines within CategoryLineThreshold, CWE-related → 0.3–0.5
//  5. Same-line: overlapping lines, CWE unrelated → confidence 0.2
//
// CWE IDs are normalized before comparison: "CWE-89", "cwe-89",
// "CWE-89: SQL Injection", and "89" all compare equal.
//
// Each annotation matches at most one finding (best match wins).
// Each finding matches at most one annotation.
//
// cweSets maps an annotation (evidence) ID to its vulnerability's full
// acceptable-CWE set, pre-normalized to ints. When present, matchScore
// checks the finding's CWE against every entry in the set and takes
// the best distance — so a finding reporting CWE-620 exact-matches a
// vuln whose set is {620, 352, 640} instead of hierarchy-matching
// whichever single CWE the compat shim happened to surface. When nil
// (the pre-010 path, and most tests), the single CWE on the Annotation
// struct is used and this degrades to the old behaviour.
func (m *Matcher) Match(findings []store.Finding, annotations []store.Annotation, cweSets map[int64][]int) ([]store.FindingMatch, error) {
	if len(findings) == 0 || len(annotations) == 0 {
		return []store.FindingMatch{}, nil
	}

	// Build annotation lookup by file path for efficiency
	annotationsByFile := make(map[string][]store.Annotation)
	for _, a := range annotations {
		annotationsByFile[normalizePath(a.FilePath)] = append(annotationsByFile[normalizePath(a.FilePath)], a)
	}

	// Collect all candidate matches
	var candidates []candidateMatch

	for i, f := range findings {
		normalizedFindingPath := normalizePath(f.FilePath)
		fileAnnotations, ok := annotationsByFile[normalizedFindingPath]

		// Fallback: if the finding path ends with exactly one known annotation
		// path suffix, use that file's annotations. Handles absolute paths
		// from CLI scanners and relative paths with extra directory prefixes
		// (e.g. finding "app/routes/api.js" matching annotation "routes/api.js"
		// when the scanner reports paths from a parent directory).
		if !ok {
			if suffixAnnotations, found := lookupByUniqueSuffix(normalizedFindingPath, annotationsByFile); found {
				fileAnnotations = suffixAnnotations
				ok = true
			}
		}

		if !ok {
			continue
		}

		for _, a := range fileAnnotations {
			matchType, confidence := m.matchScore(f, a, cweSets)
			if matchType != "" {
				candidates = append(candidates, candidateMatch{
					FindingIdx:   i,
					AnnotationID: a.ID,
					MatchType:    matchType,
					Confidence:   confidence,
					startGap:     abs(f.StartLine - a.StartLine),
				})
			}
		}
	}

	// Sort candidates by confidence descending, with deterministic
	// tiebreaks. sort.Slice is not stable — equal-confidence candidates
	// land in whatever order the quicksort partitioning leaves them,
	// which changes when the candidate list changes size. That made the
	// greedy assignment sensitive to unrelated changes elsewhere in the
	// matcher. Stable sort + explicit tiebreaks fix it.
	sort.SliceStable(candidates, func(i, j int) bool {
		ci, cj := candidates[i], candidates[j]
		if ci.Confidence != cj.Confidence {
			return ci.Confidence > cj.Confidence
		}
		// Same confidence: prefer the annotation anchored closest to the
		// finding's start. This is the wide-range disambiguation — a
		// finding at 88-166 should match the annotation at 88, not the
		// one at 140, even though both overlap.
		if ci.startGap != cj.startGap {
			return ci.startGap < cj.startGap
		}
		// Full determinism: lower annotation ID wins.
		return ci.AnnotationID < cj.AnnotationID
	})

	// Greedily assign best matches, ensuring 1-to-1 constraint
	usedFindings := make(map[int]bool)
	usedAnnotations := make(map[int64]bool)
	var matches []store.FindingMatch

	for _, c := range candidates {
		if usedFindings[c.FindingIdx] || usedAnnotations[c.AnnotationID] {
			continue
		}

		usedFindings[c.FindingIdx] = true
		usedAnnotations[c.AnnotationID] = true

		matches = append(matches, store.FindingMatch{
			FindingID:    findings[c.FindingIdx].ID,
			AnnotationID: c.AnnotationID,
			MatchType:    string(c.MatchType),
			Confidence:   sql.NullFloat64{Float64: c.Confidence, Valid: true},
		})
	}

	return matches, nil
}

// matchScore determines the match type and confidence between a finding and annotation.
// Returns empty string for MatchType if no match.
//
// Line distance is computed between the finding's line range [StartLine, EndLine]
// and the annotation's line range [StartLine, EndLine]. If the ranges overlap,
// the distance is 0. If EndLine is not set, StartLine is used as both endpoints.
func (m *Matcher) matchScore(f store.Finding, a store.Annotation, cweSets map[int64][]int) (MatchType, float64) {
	lineDistance := rangeDistance(
		f.StartLine, endLineOrStart(f.EndLine, f.StartLine),
		a.StartLine, endLineOrStart(a.EndLine, a.StartLine),
	)

	// Normalize CWE strings to ints. "CWE-89" / "cwe-89" /
	// "CWE-89: SQL Injection" / "89" all become 89. Prior to this the
	// matcher compared raw strings, so a SARIF rule ID carrying the
	// canonical name never matched a bare "CWE-89" annotation.
	fCWE, fHasCWE := 0, false
	if f.CWEID.Valid {
		fCWE, fHasCWE = cwe.Normalize(f.CWEID.String)
	}
	aCWE, aHasCWE := 0, false
	if a.CWEID.Valid {
		aCWE, aHasCWE = cwe.Normalize(a.CWEID.String)
	}

	// Distance through the MITRE tree: 0 = identical, 1 = parent/child or
	// curated pair, 2 = siblings or shared category, 3+ = looser ancestor,
	// -1 = unrelated within CWEMaxDepth. Computed once, reused by every
	// tier below.
	//
	// When this annotation (evidence row) has a CWE set, check against
	// every entry and take the best. The compat shim's a.CWEID only
	// carries one CWE from the set, so without this a finding reporting
	// CWE-620 against a {620, 352} vuln would hierarchy-match at 0.95
	// instead of exact-matching at 1.0 — not wrong, but needlessly weak.
	cweDist := cwe.Unrelated
	if fHasCWE {
		if set := cweSets[a.ID]; len(set) > 0 {
			for _, candidate := range set {
				if d := cwe.Distance(fCWE, candidate, m.CWEMaxDepth); d != cwe.Unrelated {
					if cweDist == cwe.Unrelated || d < cweDist {
						cweDist = d
					}
					if cweDist == 0 {
						break // can't do better
					}
				}
			}
		} else if aHasCWE {
			cweDist = cwe.Distance(fCWE, aCWE, m.CWEMaxDepth)
		}
	}

	// Exact: overlapping lines, identical CWE (distance 0), OR either side
	// didn't set a CWE — in which case location alone is decisive.
	if lineDistance == 0 && (cweDist == 0 || !fHasCWE || !aHasCWE) {
		return MatchTypeExact, 1.0
	}

	// Hierarchy: overlapping lines, CWE-related but not identical. This is
	// the tier the CWE package exists for — "definitely the same code,
	// probably the same bug." A scanner reporting CWE-862 where the
	// annotation says CWE-639 lands here at high confidence instead of
	// falling through to same_line at 0.2.
	if lineDistance == 0 && cweDist > 0 {
		conf := m.HierarchyBaseConfidence - float64(cweDist-1)*m.HierarchyDepthPenalty
		return MatchTypeHierarchy, conf
	}

	// Fuzzy: nearby lines, CWE-related (or one side blank). Distance 0 in
	// the CWE tree with nonzero line distance lands here too — same CWE,
	// slightly different line, is fuzzy-tier territory.
	if lineDistance <= m.FuzzyLineThreshold {
		if cweDist != cwe.Unrelated || !fHasCWE || !aHasCWE {
			conf := m.calculateConfidence(lineDistance, m.FuzzyLineThreshold, m.FuzzyMinConfidence, m.FuzzyMaxConfidence)
			return MatchTypeFuzzy, conf
		}
	}

	// Category: wider line window, CWE-related required (no blank-CWE
	// rescue at this distance — too loose).
	if lineDistance <= m.CategoryLineThreshold && cweDist != cwe.Unrelated {
		conf := m.calculateConfidence(lineDistance, m.CategoryLineThreshold, m.CategoryMinConfidence, m.CategoryMaxConfidence)
		return MatchTypeCategory, conf
	}

	// Same-line fallback: overlapping lines, CWE unrelated. Kept as a
	// safety net for CWE drift the hierarchy/curated list doesn't cover
	// yet. Low confidence so it loses the greedy assignment to any
	// better-explained match.
	if lineDistance == 0 {
		return MatchTypeSameLine, m.SameLineConfidence
	}

	return "", 0
}

// rangeDistance computes the gap between two line ranges [aStart, aEnd] and [bStart, bEnd].
// Returns 0 if the ranges overlap, otherwise the distance between the closest endpoints.
func rangeDistance(aStart, aEnd, bStart, bEnd int) int {
	if aStart <= bEnd && bStart <= aEnd {
		return 0 // ranges overlap
	}
	if aEnd < bStart {
		return bStart - aEnd
	}
	return aStart - bEnd
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// endLineOrStart returns EndLine if valid, otherwise falls back to startLine.
func endLineOrStart(endLine sql.NullInt64, startLine int) int {
	if endLine.Valid && int(endLine.Int64) >= startLine {
		return int(endLine.Int64)
	}
	return startLine
}

// calculateConfidence computes confidence based on line distance.
// Formula: maxConfidence - (lineDistance / maxDistance) * (maxConfidence - minConfidence)
func (m *Matcher) calculateConfidence(lineDistance, maxDistance int, minConfidence, maxConfidence float64) float64 {
	if maxDistance == 0 {
		return maxConfidence
	}
	ratio := float64(lineDistance) / float64(maxDistance)
	return maxConfidence - ratio*(maxConfidence-minConfidence)
}

// PropagateGroups synthesizes match_type='group' rows for annotations that
// weren't matched directly but share a group with an annotation that was.
// Use case: a scanner reports one consolidated IDOR finding that matches
// annotation A; annotations B–F (same group, different endpoints exhibiting
// the same systemic gap) should score as TP, not FN.
//
// Each synthesized row reuses the finding ID that satisfied the group — the
// attribution is "this finding satisfied the group, therefore this
// annotation." Confidence is the matcher's GroupConfidence, independent of
// how strong the direct match was; the group link is about the annotation
// set's structure, not the scanner's output.
//
// The returned rows append to the direct matches. Persist both sets;
// ComputeMetrics then sees every group-rescued annotation in the matched
// set — there is no separate rescue path at metrics time. The
// match_type='group' column value means you can still tell the difference
// in queries.
func (m *Matcher) PropagateGroups(direct []store.FindingMatch, groups map[int64][]int64) []store.FindingMatch {
	if len(groups) == 0 || len(direct) == 0 {
		return nil
	}

	// annotation → the finding that matched it. When a group is satisfied
	// by multiple members, we pick one finding (the first seen) to attribute
	// the propagated rows to — arbitrary but deterministic.
	findingFor := make(map[int64]int64, len(direct))
	for _, d := range direct {
		findingFor[d.AnnotationID] = d.FindingID
	}

	// group → the finding that satisfied it (via any member).
	groupFinding := make(map[int64]int64)
	for ann, gids := range groups {
		fid, matched := findingFor[ann]
		if !matched {
			continue
		}
		for _, g := range gids {
			if _, already := groupFinding[g]; !already {
				groupFinding[g] = fid
			}
		}
	}

	// For every unmatched annotation in a satisfied group, emit a group row.
	// The UNIQUE(finding_id, annotation_id) constraint means the same
	// finding can satisfy multiple annotations in the same group without
	// conflict — different annotation_id each row.
	var out []store.FindingMatch
	for ann, gids := range groups {
		if _, matched := findingFor[ann]; matched {
			continue // already has a direct match
		}
		for _, g := range gids {
			fid, satisfied := groupFinding[g]
			if !satisfied {
				continue
			}
			out = append(out, store.FindingMatch{
				FindingID:    fid,
				AnnotationID: ann,
				MatchType:    string(MatchTypeGroup),
				Confidence:   sql.NullFloat64{Float64: m.GroupConfidence, Valid: true},
			})
			break // one group is enough; don't emit duplicates
		}
	}
	return out
}

// normalizePath canonicalizes a file path so that scanner findings and
// ground-truth annotations compare equal regardless of how each side
// reports locations. It handles:
//   - OS-specific separators (backslash → forward slash)
//   - Redundant . and .. segments (path.Clean)
//   - Common container mount prefixes (/target/, /src/, /app/)
//   - Leading "./" and bare "/" left after prefix stripping
//   - Trailing slashes
func normalizePath(p string) string {
	// Uniform separators — everything downstream uses forward slashes.
	// strings.ReplaceAll instead of filepath.ToSlash because ToSlash only
	// converts the *host* OS separator; on Linux/macOS it's a no-op for
	// backslashes, which Windows-origin SARIF files may contain.
	p = strings.ReplaceAll(p, "\\", "/")

	// Clean redundant segments: "a/./b/../c" → "a/c".
	// path.Clean (not filepath.Clean) so the result stays slash-separated
	// on Windows hosts processing Linux-container output.
	p = path.Clean(p)

	// Strip well-known container mount prefixes. The scanner Docker runner
	// mounts the corpus at /target; other common images use /src or /app.
	for _, prefix := range []string{"/target/", "/src/", "/app/"} {
		if strings.HasPrefix(p, prefix) {
			p = p[len(prefix):]
			break
		}
	}

	// Drop leading "./" and "/" so both "./routes/api.js" and
	// "/routes/api.js" collapse to "routes/api.js".
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "/")

	return p
}

func isAbsoluteLikePath(p string) bool {
	if filepath.IsAbs(p) {
		return true
	}
	// Support Windows-style absolute paths even on non-Windows hosts.
	ps := filepath.ToSlash(p)
	return len(ps) >= 3 && ((ps[0] >= 'a' && ps[0] <= 'z') || (ps[0] >= 'A' && ps[0] <= 'Z')) && ps[1] == ':' && ps[2] == '/'
}

func lookupByUniqueSuffix(findingPath string, annotationsByFile map[string][]store.Annotation) ([]store.Annotation, bool) {
	findingPath = filepath.ToSlash(findingPath)

	var best []store.Annotation
	bestLen := -1
	ambiguous := false

	for annotationPath, annotations := range annotationsByFile {
		candidate := filepath.ToSlash(annotationPath)
		if findingPath == candidate || strings.HasSuffix(findingPath, "/"+candidate) || strings.HasSuffix(candidate, "/"+findingPath) {
			if len(candidate) > bestLen {
				best = annotations
				bestLen = len(candidate)
				ambiguous = false
			} else if len(candidate) == bestLen {
				ambiguous = true
			}
		}
	}

	if bestLen < 0 || ambiguous {
		return nil, false
	}
	return best, true
}
