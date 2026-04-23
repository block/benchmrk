package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

var triageCmd = &cobra.Command{
	Use:   "triage <run-id>",
	Short: "Triage unmatched findings from a scan run",
	Long: `List and manage dispositions for unmatched findings (scanner detections with no ground-truth entry).

By default, lists all unmatched findings with their current disposition status.
Use --set to assign a disposition to a specific finding.
Use --promote to write dispositions into ground truth.

Promotion:
  tp → new status:valid vulnerability (or evidence on an existing one via --attach-to)
  fp → new status:invalid vulnerability (a decoy; future scanners flagging it score FP)
  needs_review → not promoted

--attach-to <name> adds tp findings as evidence rows on an existing vulnerability
instead of creating new ones. Use when the finding is another manifestation of a
bug already in ground truth. fp findings ignore --attach-to (you can't attach a
false positive to a real vulnerability).

Promotion is idempotent: a finding that already has a match is skipped. Each
promoted finding gets a match row written immediately, so re-running --promote
or re-running analyze reflects the change without a re-score.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		runID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid run ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		setFindingID, _ := cmd.Flags().GetInt64("set")
		disposition, _ := cmd.Flags().GetString("disposition")
		notes, _ := cmd.Flags().GetString("notes")
		promote, _ := cmd.Flags().GetBool("promote")
		criticality, _ := cmd.Flags().GetString("criticality")
		attachTo, _ := cmd.Flags().GetString("attach-to")

		// --set mode: assign a disposition to a specific finding
		if setFindingID > 0 {
			if disposition == "" {
				return fmt.Errorf("--disposition is required when using --set")
			}
			typedDisp := store.Disposition(disposition)
			if !store.IsValidDisposition(typedDisp) {
				return fmt.Errorf("invalid disposition %q, must be one of: tp, fp, needs_review", disposition)
			}

			// Verify finding exists and belongs to this run
			finding, err := globalStore.GetFinding(ctx, setFindingID)
			if err != nil {
				return fmt.Errorf("finding %d not found: %w", setFindingID, err)
			}
			if finding.RunID != runID {
				return fmt.Errorf("finding %d does not belong to run %d", setFindingID, runID)
			}

			d := &store.FindingDisposition{
				FindingID:   setFindingID,
				Disposition: typedDisp,
				Notes:       sql.NullString{String: notes, Valid: notes != ""},
			}
			_, err = globalStore.CreateDisposition(ctx, d)
			if err != nil {
				return fmt.Errorf("set disposition: %w", err)
			}
			fmt.Printf("Finding %d dispositioned as %q\n", setFindingID, disposition)
			return nil
		}

		// --promote mode: convert tp-dispositioned findings to annotations
		if promote {
			return promoteFindings(ctx, runID, criticality, attachTo)
		}

		// Default: list unmatched findings with dispositions
		return listTriageFindings(ctx, runID)
	},
}

func listTriageFindings(ctx context.Context, runID int64) error {
	svc := analysis.NewService(globalStore, nil)
	detail, err := svc.AnalyzeRunDetail(ctx, runID)
	if err != nil {
		return fmt.Errorf("analyze run detail: %w", err)
	}

	// Collect unmatched findings
	var unmatched []analysis.FindingResult
	for _, fr := range detail.FindingResults {
		if !fr.Matched {
			unmatched = append(unmatched, fr)
		}
	}

	if len(unmatched) == 0 {
		fmt.Println("No unmatched findings to triage.")
		return nil
	}

	// Count triage stats
	triaged := 0
	tpCount := 0
	fpCount := 0
	reviewCount := 0
	for _, fr := range unmatched {
		if fr.Disposition != "" {
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

	fmt.Printf("Unmatched Findings for Run %d (%d total, %d triaged)\n", runID, len(unmatched), triaged)
	if triaged > 0 {
		fmt.Printf("  Dispositions: %d tp, %d fp, %d needs_review, %d untriaged\n",
			tpCount, fpCount, reviewCount, len(unmatched)-triaged)
	}
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tFILE\tLINE\tCWE\tRULE\tSEVERITY\tMESSAGE\tDISPOSITION")
	for _, fr := range unmatched {
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
	w.Flush()

	fmt.Println()
	fmt.Println("Disposition:  benchmrk triage <run-id> --set <id> --disposition tp|fp|needs_review --notes \"...\"")
	fmt.Println("Promote:      benchmrk triage <run-id> --promote [--criticality must|should|may] [--attach-to <vuln>]")

	return nil
}

func promoteFindings(ctx context.Context, runID int64, criticality, attachTo string) error {
	run, err := globalStore.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("get run: %w", err)
	}

	if criticality == "" {
		criticality = "should"
	}
	if criticality != "must" && criticality != "should" && criticality != "may" {
		return fmt.Errorf("--criticality must be must|should|may, got %q", criticality)
	}

	// Resolve --attach-to upfront so a typo fails before touching data.
	// attachVuln == nil means "create fresh vulns for each tp."
	var attachVuln *store.Vulnerability
	if attachTo != "" {
		attachVuln, err = globalStore.GetVulnerabilityByName(ctx, run.ProjectID, attachTo)
		if err != nil {
			return fmt.Errorf("--attach-to %q: no vulnerability by that name in project (check 'annotate list')", attachTo)
		}
		if attachVuln.Status != "valid" {
			// Attaching verified-real evidence to an invalid decoy would
			// make the decoy satisfied → matched-FP. Almost certainly not
			// what anyone wants.
			return fmt.Errorf("--attach-to %q: vulnerability has status=%s; can only attach tp findings to valid vulnerabilities", attachTo, attachVuln.Status)
		}
	}

	dispositions, err := globalStore.ListDispositionsByRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("list dispositions: %w", err)
	}

	// Idempotency: a finding that already has a match row was either
	// promoted on a previous --promote run or matched by the regular
	// scorer. Either way it's attributed; skip it. This is what makes
	// repeated --promote safe, and lets you promote in batches (first
	// the standalone tps, then --attach-to for a cluster) without the
	// earlier batch getting re-processed.
	matches, err := globalStore.ListFindingMatchesByRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("list matches: %w", err)
	}
	alreadyMatched := make(map[int64]bool, len(matches))
	for _, m := range matches {
		alreadyMatched[m.FindingID] = true
	}

	var promotedTP, promotedFP, skipped int
	for _, d := range dispositions {
		if d.Disposition != "tp" && d.Disposition != "fp" {
			continue // needs_review stays in limbo
		}
		if alreadyMatched[d.FindingID] {
			skipped++
			continue
		}

		finding, err := globalStore.GetFinding(ctx, d.FindingID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: finding %d not found, skipping: %v\n", d.FindingID, err)
			continue
		}

		var evidenceID int64
		var action string

		switch {
		case d.Disposition == store.DispositionTP && attachVuln != nil:
			// Attach as new evidence on an existing vuln. The vuln keeps
			// its criticality and CWE set; we're just adding a location.
			// Also add the finding's CWE to the set if it's new — the
			// scanner reported this CWE for a reason, and the set is
			// supposed to capture "every CWE a reasonable tool might use."
			evidenceID, err = globalStore.CreateEvidence(ctx, &store.Evidence{
				VulnID:    attachVuln.ID,
				FilePath:  finding.FilePath,
				StartLine: finding.StartLine,
				EndLine:   finding.EndLine,
				Role:      "sink",
				Category:  findingCategory(finding),
				Severity:  findingSeverity(finding),
			})
			if err == nil && finding.CWEID.Valid && finding.CWEID.String != "" {
				_ = globalStore.AddVulnCWE(ctx, attachVuln.ID, finding.CWEID.String)
			}
			action = fmt.Sprintf("attached to %q", attachVuln.Name)
			promotedTP++

		case d.Disposition == store.DispositionTP:
			evidenceID, err = createTriageVuln(ctx, run.ProjectID, finding, d, "valid", criticality)
			action = fmt.Sprintf("new %s-tier vuln", criticality)
			promotedTP++

		default: // fp
			// fp → invalid. The human verified this is NOT a bug. Writing
			// it down means: the next scanner that flags this line scores
			// a matched-FP (attributed, with the triage notes attached)
			// instead of an anonymous unmatched-FP; and a scanner that
			// correctly stays quiet scores a TN it couldn't have scored
			// before because there was nothing here to not-match.
			//
			// --attach-to is ignored for fp: you can't attach a verified
			// non-bug to a real vulnerability. Criticality on an invalid
			// decoy is arbitrary — tier recall only counts valid vulns —
			// so 'should' is as good as anything.
			evidenceID, err = createTriageVuln(ctx, run.ProjectID, finding, d, "invalid", "should")
			action = "new invalid decoy"
			promotedFP++
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to promote finding %d: %v\n", d.FindingID, err)
			if d.Disposition == store.DispositionTP {
				promotedTP--
			} else {
				promotedFP--
			}
			continue
		}

		// Write the match immediately. This is what makes promotion take
		// effect on the NEXT analyze without clearing finding_matches:
		// the finding is now matched, so it drops out of the unmatched-FP
		// bucket and into TP (tp→valid) or matched-FP (fp→invalid).
		// match_type 'manual' distinguishes triage-created attribution
		// from matcher-computed attribution in queries.
		_, _ = globalStore.CreateFindingMatch(ctx, &store.FindingMatch{
			FindingID:    finding.ID,
			AnnotationID: evidenceID, // evidence_id column; field name is compat
			MatchType:    "manual",
			Confidence:   sql.NullFloat64{Float64: 1.0, Valid: true},
		})

		if verbose {
			fmt.Printf("  finding %d (%s:%d) → %s\n", finding.ID, finding.FilePath, finding.StartLine, action)
		}
	}

	switch {
	case promotedTP+promotedFP == 0 && skipped == 0:
		fmt.Println("Nothing to promote. Disposition findings with --set first.")
	case promotedTP+promotedFP == 0:
		fmt.Printf("Nothing to promote (%d already matched).\n", skipped)
	default:
		fmt.Printf("Promoted: %d tp → valid, %d fp → invalid", promotedTP, promotedFP)
		if skipped > 0 {
			fmt.Printf(" (%d already matched, skipped)", skipped)
		}
		fmt.Println(".")
		fmt.Println("Metrics reflect this immediately — no re-score needed.")
	}
	return nil
}

// createTriageVuln builds a single-evidence vulnerability from a
// triaged finding. Goes through the native vuln API rather than the
// compat shim so criticality is settable. The triage notes land in the
// vulnerability description — that's where the "why is/isn't this a
// bug" explanation belongs, and it survives export.
func createTriageVuln(ctx context.Context, projectID int64, f *store.Finding, d store.FindingDisposition, status, criticality string) (evidenceID int64, err error) {
	// Name: the finding's rule ID when the scanner provides one (it's
	// usually a decent identifier — "sql-injection-string-concat" beats
	// "category @ file:line"), else a location-derived fallback
	// matching what migration 010 did for solo annotations.
	name := fmt.Sprintf("%s @ %s:%d", findingCategory(f), f.FilePath, f.StartLine)
	if f.RuleID.Valid && f.RuleID.String != "" {
		name = fmt.Sprintf("%s @ %s:%d", f.RuleID.String, f.FilePath, f.StartLine)
	}

	// Description: scanner message first (what the tool thinks is
	// wrong), then the triage notes (what the human verified). For fp
	// the notes are the interesting part — that's where "not actually
	// exploitable because X" lives.
	var desc sql.NullString
	parts := []string{}
	if f.Message.Valid && f.Message.String != "" {
		parts = append(parts, f.Message.String)
	}
	if d.Notes.Valid && d.Notes.String != "" {
		parts = append(parts, "[triage] "+d.Notes.String)
	}
	if len(parts) > 0 {
		desc = sql.NullString{String: joinNonEmpty(parts, "\n\n"), Valid: true}
	}

	vid, err := globalStore.CreateVulnerability(ctx, &store.Vulnerability{
		ProjectID:   projectID,
		Name:        name,
		Description: desc,
		Criticality: criticality,
		Status:      status,
	})
	if err != nil {
		return 0, fmt.Errorf("create vulnerability: %w", err)
	}

	eid, err := globalStore.CreateEvidence(ctx, &store.Evidence{
		VulnID:    vid,
		FilePath:  f.FilePath,
		StartLine: f.StartLine,
		EndLine:   f.EndLine,
		Role:      "sink",
		Category:  findingCategory(f),
		Severity:  findingSeverity(f),
	})
	if err != nil {
		return 0, fmt.Errorf("create evidence: %w", err)
	}

	if f.CWEID.Valid && f.CWEID.String != "" {
		_ = globalStore.AddVulnCWE(ctx, vid, f.CWEID.String)
	}
	_ = globalStore.AddVulnAnnotator(ctx, vid, "triage")

	return eid, nil
}

func findingCategory(f *store.Finding) string {
	if f.CWEID.Valid && f.CWEID.String != "" {
		return analysis.GetCategory(f.CWEID.String)
	}
	return "unknown"
}

func findingSeverity(f *store.Finding) string {
	if f.Severity.Valid && f.Severity.String != "" {
		return f.Severity.String
	}
	return "medium"
}

func joinNonEmpty(parts []string, sep string) string {
	out := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		if out != "" {
			out += sep
		}
		out += p
	}
	return out
}

func init() {
	triageCmd.Flags().Int64("set", 0, "finding ID to set disposition on")
	triageCmd.Flags().String("disposition", "", "disposition value: tp, fp, or needs_review")
	triageCmd.Flags().String("notes", "", "optional notes for the disposition")
	triageCmd.Flags().Bool("promote", false, "write tp→valid and fp→invalid ground-truth entries")
	triageCmd.Flags().String("criticality", "should", "criticality tier for promoted tp findings: must|should|may")
	triageCmd.Flags().String("attach-to", "", "add tp findings as evidence on this existing vulnerability (by name) instead of creating new ones")

	rootCmd.AddCommand(triageCmd)
}
