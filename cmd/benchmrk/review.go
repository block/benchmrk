package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/report"
	"github.com/spf13/cobra"
)

var (
	reviewOutput  string
	reviewContext int
	reviewCross   bool
	reviewSrcRoot string
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Generate a finding-centric HTML triage page",
	Long: `Render findings as a scrollable triage document with everything needed
to make the tp/fp call inline: full scanner message, source context,
near-miss evidence, and a prefilled disposition command per card.

Two modes:
  run <id>     pull from the DB with full match/disposition context
  sarif <file> render any SARIF file, no DB required`,
}

var reviewRunCmd = &cobra.Command{
	Use:   "run <run-id>",
	Short: "Review findings from a stored run",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		runID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid run ID: %w", err)
		}
		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		asvc := analysis.NewService(globalStore, nil)
		data, err := report.BuildReviewFromRun(cmd.Context(), globalStore, asvc, runID, report.ReviewOptions{
			ContextLines: reviewContext,
			CrossRun:     reviewCross,
		})
		if err != nil {
			return fmt.Errorf("build review: %w", err)
		}

		return writeReview(data, reviewOutput)
	},
}

var reviewSarifCmd = &cobra.Command{
	Use:   "sarif <file.sarif>",
	Short: "Review findings from a SARIF file (no DB required)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := report.BuildReviewFromSARIF(args[0], reviewSrcRoot, reviewContext)
		if err != nil {
			return fmt.Errorf("build review: %w", err)
		}
		return writeReview(data, reviewOutput)
	},
}

func writeReview(data *report.ReviewData, out string) error {
	var w io.Writer = os.Stdout
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			return fmt.Errorf("create %s: %w", out, err)
		}
		defer f.Close()
		w = f
	}
	if err := report.FormatReviewHTML(data, w); err != nil {
		return fmt.Errorf("write html: %w", err)
	}
	if out != "" {
		fmt.Fprintf(os.Stderr, "Wrote %s\n", out)
	}
	return nil
}

func init() {
	reviewCmd.PersistentFlags().StringVarP(&reviewOutput, "output", "o", "", "output file (default: stdout)")
	reviewCmd.PersistentFlags().IntVar(&reviewContext, "context-lines", 5, "lines of source context around each finding")

	reviewRunCmd.Flags().BoolVar(&reviewCross, "cross-run", false, "show which sibling runs in the same experiment also flagged each location")

	reviewSarifCmd.Flags().StringVar(&reviewSrcRoot, "source-root", "", "project root for reading code context (optional)")

	reviewCmd.AddCommand(reviewRunCmd)
	reviewCmd.AddCommand(reviewSarifCmd)
	rootCmd.AddCommand(reviewCmd)
}
