package report

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/analysis/cwe"
	"github.com/block/benchmrk/internal/sarif"
	"github.com/block/benchmrk/internal/store"
)

// ReviewData is the finding-centric triage view. Unlike ReportData it
// is single-run (or single-SARIF) and puts unmatched findings first and
// loudest — those are the ones that need a human call.
type ReviewData struct {
	Mode        string // "run" | "sarif"
	Meta        ReviewMeta
	Summary     *analysis.Metrics // nil in sarif mode
	Unmatched   []FindingCard     // triage targets
	Matched     []FindingCard     // verification view, low-confidence first
	Unsatisfied []VulnCard        // FN vulns — nil in sarif mode
	CrossRun    bool              // was --cross-run requested? lets the template say "only this run" when CrossRunHit is empty
	GeneratedAt time.Time
}

type ReviewMeta struct {
	RunID       int64
	Scanner     string
	Project     string
	ProjectPath string
	ToolName    string // sarif mode: tool.driver.name
	ToolVersion string
	SourceRoot  string // sarif mode: --source-root
}

// FindingCard is one triage card. Every nil pointer field degrades
// gracefully in the template — SARIF-standalone mode populates almost
// nothing beyond Finding, RuleName, and Context.
type FindingCard struct {
	Finding     store.Finding
	RuleName    string                    // human-readable rule title (SARIF mode); empty if unavailable
	Context     *SourceContext            // ±N lines from disk; nil if unreadable
	Match       *MatchInfo                // nil for unmatched
	Disposition *store.FindingDisposition // nil if unset
	NearMiss    *NearMiss                 // unmatched only; nil if nothing close
	CrossRun    []CrossRunHit             // --cross-run only
	TriageCmd   string                    // prefilled CLI; unmatched only
}

type MatchInfo struct {
	MatchType  string
	Confidence float64
	VulnName   string
	Evidence   store.Evidence
}

type SourceContext struct {
	Lines    []SourceLine
	Language string // for CSS class, best-effort from extension
}

type SourceLine struct {
	N      int
	Text   string
	Target bool // inside the finding's [StartLine, EndLine]
}

// NearMiss explains why the closest evidence didn't match. This is the
// "is this a matching artifact or a real new thing?" helper.
type NearMiss struct {
	Evidence  store.Evidence
	VulnName  string
	LineDelta int
	CWEDist   int // from cwe.Distance; -1 = unrelated
	Why       string
}

type CrossRunHit struct {
	RunID     int64
	Scanner   string
	Iteration int
	Matched   bool // did that run's finding at this location get a match?
}

type VulnCard struct {
	Vuln           store.Vulnerability
	Evidence       []store.Evidence
	CWEs           []string
	NearestFinding *NearFinding // nil if nothing in any evidence file
}

type NearFinding struct {
	Finding   store.Finding
	LineDelta int
	Why       string
}

// ReviewStore is the subset of *store.Store the run-mode builder reads.
// It's wide because triage cards pull from the whole schema — finding,
// disposition, evidence, vuln, CWE set, sibling runs. In practice the
// CLI passes globalStore directly.
type ReviewStore interface {
	GetRun(ctx context.Context, id int64) (*store.Run, error)
	GetScanner(ctx context.Context, id int64) (*store.Scanner, error)
	GetProject(ctx context.Context, id int64) (*store.CorpusProject, error)
	ListFindingsByRun(ctx context.Context, runID int64) ([]store.Finding, error)
	ListFindingMatchesByRun(ctx context.Context, runID int64) ([]store.FindingMatch, error)
	ListDispositionsByRun(ctx context.Context, runID int64) ([]store.FindingDisposition, error)
	ListEvidenceByProject(ctx context.Context, projectID int64) ([]store.Evidence, error)
	ListVulnerabilitiesByProject(ctx context.Context, projectID int64) ([]store.Vulnerability, error)
	ListVulnCWEs(ctx context.Context, projectID int64) (map[int64][]string, error)
	ListUnsatisfiedVulns(ctx context.Context, runID, projectID int64) ([]store.Vulnerability, error)
	ListRunsByExperiment(ctx context.Context, experimentID int64) ([]store.Run, error)
}

type ReviewOptions struct {
	ContextLines int  // ±N lines around finding; default 5
	CrossRun     bool // look up sibling runs in the same experiment
}

// BuildReviewFromRun assembles a ReviewData from a stored run. The
// analysis service is run first so matches and metrics reflect current
// matcher logic; the store is then read directly for the card details
// that AnalyzeRunDetail doesn't carry (full disposition structs,
// evidence rows, vuln CWE sets).
func BuildReviewFromRun(ctx context.Context, st ReviewStore, asvc *analysis.Service, runID int64, opts ReviewOptions) (*ReviewData, error) {
	if opts.ContextLines <= 0 {
		opts.ContextLines = 5
	}

	run, err := st.GetRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("get run: %w", err)
	}
	scanner, err := st.GetScanner(ctx, run.ScannerID)
	if err != nil {
		return nil, fmt.Errorf("get scanner: %w", err)
	}
	project, err := st.GetProject(ctx, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	// AnalyzeRunDetail gives us classification + match info per finding
	// and ensures matches are computed. The vuln-level Metrics struct
	// (TP=satisfied vulns) is what the summary shows; the per-annotation
	// counts inside detail.Metrics are noisier and not what triage wants.
	detail, err := asvc.AnalyzeRunDetail(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("analyze run: %w", err)
	}
	summary, err := asvc.AnalyzeRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("compute summary: %w", err)
	}

	// Load the bits AnalyzeRunDetail doesn't carry.
	dispositions, err := st.ListDispositionsByRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("list dispositions: %w", err)
	}
	dispByFinding := make(map[int64]*store.FindingDisposition, len(dispositions))
	for i := range dispositions {
		dispByFinding[dispositions[i].FindingID] = &dispositions[i]
	}

	evidence, err := st.ListEvidenceByProject(ctx, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	evidenceByID := make(map[int64]store.Evidence, len(evidence))
	for _, e := range evidence {
		evidenceByID[e.ID] = e
	}

	vulns, err := st.ListVulnerabilitiesByProject(ctx, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list vulns: %w", err)
	}
	vulnByID := make(map[int64]store.Vulnerability, len(vulns))
	for _, v := range vulns {
		vulnByID[v.ID] = v
	}

	cweByVuln, err := st.ListVulnCWEs(ctx, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list cwes: %w", err)
	}

	// Near-miss index: evidence rows keyed by normalized file path.
	// Cheap to build once, O(unmatched × evidence-in-same-file) to query.
	nm := buildNearMissIndex(evidence, vulnByID, cweByVuln)

	// Cross-run lookup is opt-in and hits the DB per experiment.
	var crossIdx *crossRunIndex
	if opts.CrossRun {
		crossIdx, err = buildCrossRunIndex(ctx, st, run)
		if err != nil {
			return nil, fmt.Errorf("build cross-run index: %w", err)
		}
	}

	rd := &ReviewData{
		Mode: "run",
		Meta: ReviewMeta{
			RunID:       runID,
			Scanner:     scanner.Name + " " + scanner.Version,
			Project:     project.Name,
			ProjectPath: project.LocalPath,
		},
		Summary:     summary,
		CrossRun:    opts.CrossRun,
		GeneratedAt: time.Now().UTC(),
	}

	for _, fr := range detail.FindingResults {
		card := FindingCard{
			Finding:     fr.Finding,
			Context:     readSourceContext(project.LocalPath, fr.Finding, opts.ContextLines),
			Disposition: dispByFinding[fr.Finding.ID],
		}
		if crossIdx != nil {
			card.CrossRun = crossIdx.lookup(fr.Finding)
		}

		if fr.Matched {
			// MatchedAnnotation.ID is actually an evidence ID post-010.
			ev := evidenceByID[fr.MatchedAnnotation.ID]
			card.Match = &MatchInfo{
				MatchType:  fr.MatchType,
				Confidence: fr.Confidence,
				VulnName:   vulnByID[ev.VulnID].Name,
				Evidence:   ev,
			}
			rd.Matched = append(rd.Matched, card)
		} else {
			card.NearMiss = nm.closest(fr.Finding)
			card.TriageCmd = fmt.Sprintf("benchmrk triage %d --set %d --disposition tp|fp --notes \"...\"",
				runID, fr.Finding.ID)
			rd.Unmatched = append(rd.Unmatched, card)
		}
	}

	// Unmatched: highest severity first. These are triage targets; a
	// critical FP? should be adjudicated before a note-level one. Ties
	// break on file/line so same-file findings stay clustered.
	sort.Slice(rd.Unmatched, func(i, j int) bool {
		ri, rj := sevRank(cardSev(rd.Unmatched[i])), sevRank(cardSev(rd.Unmatched[j]))
		if ri != rj {
			return ri < rj
		}
		fi, fj := rd.Unmatched[i].Finding, rd.Unmatched[j].Finding
		if fi.FilePath != fj.FilePath {
			return fi.FilePath < fj.FilePath
		}
		return fi.StartLine < fj.StartLine
	})

	// Matched: low-confidence first. Those are the ones worth eyeballing —
	// a same_line or category match at 0.2-0.4 might be the matcher being
	// generous.
	sort.Slice(rd.Matched, func(i, j int) bool {
		return rd.Matched[i].Match.Confidence < rd.Matched[j].Match.Confidence
	})

	// Unsatisfied vulns (the FNs). Attach their evidence locations and
	// the nearest finding in any of those files so the card can say
	// "scanner reported nothing within 40 lines" vs "there was a
	// finding 3 lines away with an unrelated CWE."
	unsat, err := st.ListUnsatisfiedVulns(ctx, runID, run.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("list unsatisfied: %w", err)
	}
	evByVuln := make(map[int64][]store.Evidence)
	for _, e := range evidence {
		evByVuln[e.VulnID] = append(evByVuln[e.VulnID], e)
	}
	findingsByFile := make(map[string][]store.Finding)
	for _, fr := range detail.FindingResults {
		p := normalizeReviewPath(fr.Finding.FilePath)
		findingsByFile[p] = append(findingsByFile[p], fr.Finding)
	}
	for _, v := range unsat {
		vc := VulnCard{
			Vuln:     v,
			Evidence: evByVuln[v.ID],
			CWEs:     cweByVuln[v.ID],
		}
		vc.NearestFinding = nearestFindingToVuln(vc.Evidence, findingsByFile)
		rd.Unsatisfied = append(rd.Unsatisfied, vc)
	}
	// must > should > may ordering — the critical misses first.
	sort.Slice(rd.Unsatisfied, func(i, j int) bool {
		return critRank(rd.Unsatisfied[i].Vuln.Criticality) < critRank(rd.Unsatisfied[j].Vuln.Criticality)
	})

	return rd, nil
}

// BuildReviewFromSARIF renders a SARIF file without any DB context.
// No match info, no dispositions, no near-miss — just findings grouped
// by file with messages and (if --source-root given) code context.
func BuildReviewFromSARIF(path, sourceRoot string, contextLines int) (*ReviewData, error) {
	if contextLines <= 0 {
		contextLines = 5
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sarif: %w", err)
	}
	defer f.Close()

	report, err := sarif.Parse(f)
	if err != nil {
		return nil, err
	}
	findings, err := sarif.ExtractFindings(report)
	if err != nil {
		return nil, fmt.Errorf("extract findings: %w", err)
	}

	meta := ReviewMeta{SourceRoot: sourceRoot}
	if len(report.Runs) > 0 {
		d := report.Runs[0].Tool.Driver
		meta.ToolName = d.Name
		meta.ToolVersion = d.Version
	}

	rd := &ReviewData{
		Mode:        "sarif",
		Meta:        meta,
		GeneratedAt: time.Now().UTC(),
	}

	// Highest severity first, then group by file/line within a severity
	// band. A critical at the bottom of a 200-finding page is a critical
	// nobody reads.
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := sevRank(findings[i].Severity), sevRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].FilePath != findings[j].FilePath {
			return findings[i].FilePath < findings[j].FilePath
		}
		return findings[i].StartLine < findings[j].StartLine
	})

	// SARIF mode has no DB, so store.Finding.ID is zero. Assign a 1-based
	// sequence number post-sort so each card gets a stable "#N" reference
	// humans can cite during triage.
	for i, sf := range findings {
		f := sarifToStoreFinding(sf)
		f.ID = int64(i + 1)
		card := FindingCard{Finding: f, RuleName: sf.RuleName}
		if sourceRoot != "" {
			card.Context = readSourceContext(sourceRoot, f, contextLines)
		}
		// No match context in SARIF mode — everything lands in Unmatched.
		// The template treats Mode=="sarif" specially and doesn't label
		// them FP?.
		rd.Unmatched = append(rd.Unmatched, card)
	}

	return rd, nil
}

// --- near-miss computation -------------------------------------------------

type nearMissIndex struct {
	byFile map[string][]nearMissEntry
}

type nearMissEntry struct {
	ev       store.Evidence
	vulnName string
	cwes     []int // pre-normalized
}

func buildNearMissIndex(evidence []store.Evidence, vulns map[int64]store.Vulnerability, cweByVuln map[int64][]string) *nearMissIndex {
	idx := &nearMissIndex{byFile: make(map[string][]nearMissEntry)}
	for _, e := range evidence {
		var norm []int
		for _, c := range cweByVuln[e.VulnID] {
			if n, ok := cwe.Normalize(c); ok {
				norm = append(norm, n)
			}
		}
		p := normalizeReviewPath(e.FilePath)
		idx.byFile[p] = append(idx.byFile[p], nearMissEntry{
			ev:       e,
			vulnName: vulns[e.VulnID].Name,
			cwes:     norm,
		})
	}
	return idx
}

// closest finds the evidence in the same file nearest to the finding's
// location and explains why it didn't produce a match. Returns nil when
// there's no evidence in the file at all — that's the "not a matching
// artifact, this is genuinely new" signal.
func (idx *nearMissIndex) closest(f store.Finding) *NearMiss {
	entries := idx.byFile[normalizeReviewPath(f.FilePath)]
	if len(entries) == 0 {
		return nil
	}

	fCWE, fHasCWE := 0, false
	if f.CWEID.Valid {
		fCWE, fHasCWE = cwe.Normalize(f.CWEID.String)
	}

	var best *NearMiss
	for _, e := range entries {
		delta := f.StartLine - e.ev.StartLine
		absDelta := delta
		if absDelta < 0 {
			absDelta = -absDelta
		}

		// Best CWE distance across the evidence's acceptable set, same
		// logic the matcher uses.
		dist := cwe.Unrelated
		if fHasCWE {
			for _, c := range e.cwes {
				if d := cwe.Distance(fCWE, c, 3); d != cwe.Unrelated {
					if dist == cwe.Unrelated || d < dist {
						dist = d
					}
				}
			}
		}

		if best == nil || absDelta < abs(best.LineDelta) ||
			(absDelta == abs(best.LineDelta) && dist != cwe.Unrelated && (best.CWEDist == cwe.Unrelated || dist < best.CWEDist)) {
			best = &NearMiss{
				Evidence:  e.ev,
				VulnName:  e.vulnName,
				LineDelta: delta,
				CWEDist:   dist,
			}
		}
	}

	best.Why = explainNearMiss(best.LineDelta, best.CWEDist, fHasCWE)
	return best
}

// explainNearMiss turns (lineDelta, cweDist) into a one-line hint. These
// mirror the matcher's tier boundaries so "outside fuzzy range" means
// exactly that — the finding was >5 lines from the nearest evidence.
func explainNearMiss(lineDelta, cweDist int, findingHasCWE bool) string {
	absDelta := lineDelta
	if absDelta < 0 {
		absDelta = -absDelta
	}

	switch {
	case absDelta == 0 && cweDist == cwe.Unrelated && findingHasCWE:
		return "same line, CWE unrelated — would be same_line match at conf 0.2; check if the scanner's CWE is just wrong"
	case absDelta == 0 && !findingHasCWE:
		// Matcher treats missing-CWE at lineDelta=0 as exact. If we're
		// here the greedy assignment gave this evidence to a stronger
		// candidate.
		return "same line — likely lost the greedy assignment to a better match; check what else matched this evidence"
	case absDelta == 0:
		return fmt.Sprintf("same line, CWE hierarchy dist %d — would be a hierarchy match; check what else won the evidence", cweDist)
	case absDelta <= 5 && cweDist != cwe.Unrelated:
		return fmt.Sprintf("%d lines away, CWE-related (dist %d) — inside fuzzy range; lost the greedy assignment or the evidence is already matched", absDelta, cweDist)
	case absDelta <= 5:
		return fmt.Sprintf("%d lines away, CWE unrelated — inside fuzzy range but wrong bug class", absDelta)
	case cweDist == 0:
		return fmt.Sprintf("%d lines away, same CWE — outside fuzzy range; check if scanner pointed at a different sink", absDelta)
	case cweDist != cwe.Unrelated:
		return fmt.Sprintf("%d lines away, CWE-related (dist %d) — outside fuzzy range", absDelta, cweDist)
	default:
		return fmt.Sprintf("%d lines away, CWE unrelated — different bug", absDelta)
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func nearestFindingToVuln(evidence []store.Evidence, findingsByFile map[string][]store.Finding) *NearFinding {
	var best *NearFinding
	for _, e := range evidence {
		for _, f := range findingsByFile[normalizeReviewPath(e.FilePath)] {
			d := f.StartLine - e.StartLine
			ad := d
			if ad < 0 {
				ad = -ad
			}
			if best == nil || ad < abs(best.LineDelta) {
				best = &NearFinding{Finding: f, LineDelta: d}
			}
		}
	}
	if best != nil {
		ad := abs(best.LineDelta)
		if ad == 0 {
			best.Why = "a finding landed on an evidence line but didn't match — CWE drift or greedy assignment"
		} else {
			best.Why = fmt.Sprintf("nearest finding was %d lines from evidence", ad)
		}
	}
	return best
}

// --- cross-run lookup ------------------------------------------------------

type crossRunIndex struct {
	// key: normalized file path + ":" + startLine. Coarse but matches
	// what a human means by "did anyone else flag this location."
	hits map[string][]CrossRunHit
}

func buildCrossRunIndex(ctx context.Context, st ReviewStore, run *store.Run) (*crossRunIndex, error) {
	siblings, err := st.ListRunsByExperiment(ctx, run.ExperimentID)
	if err != nil {
		return nil, err
	}

	idx := &crossRunIndex{hits: make(map[string][]CrossRunHit)}
	scannerCache := make(map[int64]string)

	for _, sib := range siblings {
		if sib.ID == run.ID || sib.Status != store.RunStatusCompleted || sib.ProjectID != run.ProjectID {
			continue
		}
		sname := scannerCache[sib.ScannerID]
		if sname == "" {
			sc, err := st.GetScanner(ctx, sib.ScannerID)
			if err != nil {
				return nil, err
			}
			sname = sc.Name
			scannerCache[sib.ScannerID] = sname
		}

		findings, err := st.ListFindingsByRun(ctx, sib.ID)
		if err != nil {
			return nil, err
		}
		matches, err := st.ListFindingMatchesByRun(ctx, sib.ID)
		if err != nil {
			return nil, err
		}
		matched := make(map[int64]bool, len(matches))
		for _, m := range matches {
			matched[m.FindingID] = true
		}

		for _, f := range findings {
			k := crossKey(f.FilePath, f.StartLine)
			idx.hits[k] = append(idx.hits[k], CrossRunHit{
				RunID:     sib.ID,
				Scanner:   sname,
				Iteration: sib.Iteration,
				Matched:   matched[f.ID],
			})
		}
	}
	return idx, nil
}

func (idx *crossRunIndex) lookup(f store.Finding) []CrossRunHit {
	return idx.hits[crossKey(f.FilePath, f.StartLine)]
}

func crossKey(path string, line int) string {
	return fmt.Sprintf("%s:%d", normalizeReviewPath(path), line)
}

// --- source context --------------------------------------------------------

// readSourceContext reads ±padding lines around the finding's range from
// disk. Returns nil on any error — file moved, binary, whatever — and
// the template falls back to Finding.Snippet.
func readSourceContext(root string, f store.Finding, padding int) *SourceContext {
	if root == "" || f.StartLine <= 0 {
		return nil
	}

	// The finding's path may carry container prefixes; strip them before
	// joining with the project root.
	rel := normalizeReviewPath(f.FilePath)
	full := filepath.Join(root, rel)

	fh, err := os.Open(full)
	if err != nil {
		return nil
	}
	defer fh.Close()

	end := f.StartLine
	if f.EndLine.Valid && int(f.EndLine.Int64) > end {
		end = int(f.EndLine.Int64)
	}
	lo := f.StartLine - padding
	if lo < 1 {
		lo = 1
	}
	hi := end + padding

	const maxLines = 400 // cap for huge findings; a 10k-line range isn't readable anyway
	if hi-lo > maxLines {
		hi = lo + maxLines
	}

	sc := &SourceContext{Language: langFromExt(rel)}
	scanner := bufio.NewScanner(fh)
	// Raise the line-length cap above the default 64k; source files can
	// have minified lines. 1MB is plenty and bounded.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	n := 0
	for scanner.Scan() {
		n++
		if n < lo {
			continue
		}
		if n > hi {
			break
		}
		line := scanner.Text()
		// Quick binary sniff: a NUL byte in the window means this isn't
		// a text file we want to render.
		if strings.IndexByte(line, 0) >= 0 {
			return nil
		}
		sc.Lines = append(sc.Lines, SourceLine{
			N:      n,
			Text:   line,
			Target: n >= f.StartLine && n <= end,
		})
	}
	if len(sc.Lines) == 0 {
		return nil
	}
	return sc
}

func langFromExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx", ".mjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".rs":
		return "rust"
	case ".cs":
		return "csharp"
	default:
		return "plaintext"
	}
}

// --- helpers ---------------------------------------------------------------

// normalizeReviewPath mirrors analysis.normalizePath (unexported) — strip
// the container mount prefix and leading ./ so finding paths and evidence
// paths compare equal.
func normalizeReviewPath(p string) string {
	p = strings.TrimPrefix(p, "/target/")
	p = strings.TrimPrefix(p, "./")
	return p
}

func critRank(c string) int {
	switch c {
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

// sevRank maps both SARIF levels (error/warning/note) and CVSS-style
// severities (critical/high/medium/low/info) onto one ordering. Lower
// rank = higher priority. Unknown/empty severities sink to the bottom.
func sevRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high", "error":
		return 1
	case "medium", "warning":
		return 2
	case "low", "note":
		return 3
	case "info", "informational", "none":
		return 4
	default:
		return 5
	}
}

// cardSev pulls the severity string out of a FindingCard, treating
// NULL as empty so sevRank sinks it.
func cardSev(c FindingCard) string {
	if c.Finding.Severity.Valid {
		return c.Finding.Severity.String
	}
	return ""
}

func sarifToStoreFinding(sf sarif.Finding) store.Finding {
	f := store.Finding{
		FilePath:  sf.FilePath,
		StartLine: sf.StartLine,
	}
	if sf.EndLine > 0 && sf.EndLine >= sf.StartLine {
		f.EndLine.Int64 = int64(sf.EndLine)
		f.EndLine.Valid = true
	}
	if sf.RuleID != "" {
		f.RuleID.String, f.RuleID.Valid = sf.RuleID, true
	}
	if sf.CWE != "" {
		f.CWEID.String, f.CWEID.Valid = sf.CWE, true
	}
	if sf.Severity != "" {
		f.Severity.String, f.Severity.Valid = sf.Severity, true
	}
	if sf.Message != "" {
		f.Message.String, f.Message.Valid = sf.Message, true
	}
	if sf.Snippet != "" {
		f.Snippet.String, f.Snippet.Valid = sf.Snippet, true
	}
	return f
}
