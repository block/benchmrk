package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

var (
	rescoreYes       bool
	rescoreClearOnly bool
	rescoreRunID     int64
)

var rescoreCmd = &cobra.Command{
	Use:   "rescore [project]",
	Short: "Clear and recompute finding matches against current ground truth",
	Long: `Rescore discards the derived finding_matches rows for a set of runs and
re-runs the matcher against the project's CURRENT annotations. Use this
when compare warns "annotation set differs across runs" — it aligns every
run to the same ground truth so the numbers are comparable again.

This is safe: finding_matches is a cache. Findings and annotations are
untouched. Each re-matched run gets a fresh matcher_version and
annotation_hash stamp.

Scope:
  rescore <project>    all completed runs on the project
  rescore --run <id>   one run only

A preview (hash spread, run count, match row count) is shown before
anything is deleted. Pass --yes to skip the prompt.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}
		ctx := context.Background()

		runs, projectID, err := resolveRescoreScope(ctx, args)
		if err != nil {
			return err
		}
		if len(runs) == 0 {
			fmt.Println("No completed runs to rescore.")
			return nil
		}

		// Guardrail: refuse to rescore against an empty ground truth.
		// Every former TP would silently become FP, every FN would
		// vanish — that's almost certainly not what the user wants,
		// and it's not reversible without re-importing annotations.
		vulns, err := globalStore.ListVulnerabilitiesByProject(ctx, projectID)
		if err != nil {
			return fmt.Errorf("check ground truth: %w", err)
		}
		if len(vulns) == 0 {
			return fmt.Errorf("project has no annotations — rescoring would turn every TP into FP.\n" +
				"  Import ground truth first:  benchmrk annotate import <project> --file <json>")
		}

		currentHash, err := globalStore.AnnotationHash(ctx, projectID)
		if err != nil {
			return fmt.Errorf("hash current annotations: %w", err)
		}

		printRescorePreview(runs, currentHash, len(vulns))

		if !rescoreYes {
			if !confirm("Proceed?") {
				fmt.Println("Aborted.")
				return nil
			}
		}

		return executeRescore(ctx, runs)
	},
}

// resolveRescoreScope turns CLI args into a (runs, projectID) pair.
// Either a project name positional or --run <id>, not both; at least one.
// Only completed runs are returned — pending/failed runs have no
// findings to match, and matching them would stamp a hash that doesn't
// reflect any actual scoring.
func resolveRescoreScope(ctx context.Context, args []string) ([]store.Run, int64, error) {
	switch {
	case len(args) == 1 && rescoreRunID != 0:
		return nil, 0, fmt.Errorf("specify either a project name or --run, not both")
	case len(args) == 0 && rescoreRunID == 0:
		return nil, 0, fmt.Errorf("specify a project name or --run <id>")
	}

	if rescoreRunID != 0 {
		run, err := globalStore.GetRun(ctx, rescoreRunID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, 0, fmt.Errorf("run %d not found", rescoreRunID)
			}
			return nil, 0, fmt.Errorf("get run: %w", err)
		}
		if run.Status != store.RunStatusCompleted {
			return nil, 0, fmt.Errorf("run %d is %s — only completed runs have findings to rescore", rescoreRunID, run.Status)
		}
		return []store.Run{*run}, run.ProjectID, nil
	}

	project, err := globalStore.GetProjectByName(ctx, args[0])
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, 0, fmt.Errorf("project %q not found", args[0])
		}
		return nil, 0, fmt.Errorf("get project: %w", err)
	}

	all, err := globalStore.ListRunsByProject(ctx, project.ID)
	if err != nil {
		return nil, 0, fmt.Errorf("list runs: %w", err)
	}
	completed := all[:0]
	for _, r := range all {
		if r.Status == store.RunStatusCompleted {
			completed = append(completed, r)
		}
	}
	return completed, project.ID, nil
}

// printRescorePreview shows what's about to happen: which runs are on
// which annotation hash now, which hash they'll all end up on, and how
// many match rows will be discarded. The hash breakdown is the same
// information compare's warning shows — it's why the user is here.
func printRescorePreview(runs []store.Run, targetHash string, vulnCount int) {
	byHash := map[string][]int64{}
	for _, r := range runs {
		h := r.AnnotationHash.String // "" for NULL → unstamped (pre-009 or never scored)
		byHash[h] = append(byHash[h], r.ID)
	}

	fmt.Printf("Target: %s (%d vulnerabilities)\n\n", shortHash(targetHash), vulnCount)

	if len(byHash) == 1 {
		// All runs already agree. Rescoring is still valid (matcher
		// may have changed, or annotations changed without a hash
		// churn if only non-scoring fields moved), but flag it.
		for h := range byHash {
			if h == targetHash {
				fmt.Printf("All %d run(s) already stamped with the target hash.\n", len(runs))
				fmt.Println("Rescore is only useful if matcher logic changed since they were scored.")
			} else {
				fmt.Printf("All %d run(s) on %s → will move to %s\n", len(runs), shortHash(h), shortHash(targetHash))
			}
		}
	} else {
		fmt.Printf("%d run(s) currently on %d different annotation sets:\n", len(runs), len(byHash))
		hashes := make([]string, 0, len(byHash))
		for h := range byHash {
			hashes = append(hashes, h)
		}
		sort.Strings(hashes)
		for _, h := range hashes {
			ids := byHash[h]
			marker := " "
			if h == targetHash {
				marker = "*" // already on target
			}
			fmt.Printf("  %s %s → runs %v\n", marker, shortHash(h), ids)
		}
		fmt.Println("  (* = already on target hash; will be rescored anyway for consistency)")
	}
	fmt.Println()
}

func shortHash(h string) string {
	if h == "" {
		return "<unstamped>"
	}
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func executeRescore(ctx context.Context, runs []store.Run) error {
	svc := analysis.NewService(globalStore, nil)

	var totalCleared int64
	for _, r := range runs {
		n, err := globalStore.ClearFindingMatchesForRun(ctx, r.ID)
		if err != nil {
			return fmt.Errorf("clear run %d: %w", r.ID, err)
		}
		totalCleared += n
	}
	fmt.Printf("Cleared %d match rows across %d runs.\n", totalCleared, len(runs))

	if rescoreClearOnly {
		fmt.Println("--clear-only: next analyze/compare will rematch lazily.")
		return nil
	}

	fmt.Println()
	for i, r := range runs {
		fmt.Printf("  [%d/%d] run %d ... ", i+1, len(runs), r.ID)
		if err := svc.MatchRun(ctx, r.ID); err != nil {
			// Don't abort the batch — one run's match failure (e.g.
			// its findings were manually deleted) shouldn't strand the
			// others in a half-cleared state. Report and move on.
			fmt.Printf("FAILED: %v\n", err)
			continue
		}
		matches, _ := globalStore.ListFindingMatchesByRun(ctx, r.ID)
		fmt.Printf("%d matches\n", len(matches))
	}
	fmt.Println("\nDone. Re-run compare to see aligned metrics.")
	return nil
}

func init() {
	rescoreCmd.Flags().BoolVarP(&rescoreYes, "yes", "y", false, "skip confirmation prompt")
	rescoreCmd.Flags().BoolVar(&rescoreClearOnly, "clear-only", false, "clear matches but don't rematch (next analyze/compare does it lazily)")
	rescoreCmd.Flags().Int64Var(&rescoreRunID, "run", 0, "rescore one run by ID instead of a whole project")
	rootCmd.AddCommand(rescoreCmd)
}
