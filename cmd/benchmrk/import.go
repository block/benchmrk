package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/block/benchmrk/internal/scanner"
	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import <scanner-name> <project-name> <output-file>",
	Short: "Import pre-existing tool output as a completed run",
	Long: `Import a pre-existing scanner output file (SARIF, semgrep-json, etc.) and
create a run record with parsed findings, without executing Docker.

The output is associated with the named scanner and project. The format is
determined from the scanner's config unless overridden with --format.`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		scannerName := args[0]
		projectName := args[1]
		outputFile := args[2]

		absPath, err := filepath.Abs(outputFile)
		if err != nil {
			return fmt.Errorf("resolve path: %w", err)
		}
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return fmt.Errorf("output file not found: %s", absPath)
		}

		format, _ := cmd.Flags().GetString("format")
		experimentID, _ := cmd.Flags().GetInt64("experiment")
		iteration, _ := cmd.Flags().GetInt("iteration")
		outputDir, _ := cmd.Flags().GetString("output-dir")

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		scannerSvc := initScannerService(outputDir)
		if scannerSvc == nil {
			return fmt.Errorf("failed to initialize scanner service")
		}

		ctx := context.Background()

		// Auto-create an ad-hoc experiment if none was specified
		if experimentID == 0 {
			expName := fmt.Sprintf("import-%s-%s-%d", scannerName, projectName, time.Now().Unix())
			experimentID, err = globalStore.CreateExperiment(ctx, &store.Experiment{
				Name:       expName,
				Iterations: 1,
			})
			if err != nil {
				return fmt.Errorf("create ad-hoc experiment: %w", err)
			}
		}

		fmt.Printf("Importing: %s -> %s x %s\n", absPath, scannerName, projectName)

		startTime := time.Now()
		run, err := scannerSvc.Scan(ctx, scannerName, projectName, scanner.ScanOptions{
			ExperimentID:   experimentID,
			Iteration:      iteration,
			ImportPath:     absPath,
			FormatOverride: format,
		})
		if err != nil {
			return fmt.Errorf("import failed: %w", err)
		}

		duration := time.Since(startTime)

		fmt.Printf("\nImport complete!\n")
		fmt.Printf("  Run ID:   %d\n", run.ID)
		fmt.Printf("  Status:   %s\n", run.Status)
		fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))

		if run.Status == store.RunStatusCompleted {
			findings, err := globalStore.ListFindingsByRun(ctx, run.ID)
			if err == nil {
				fmt.Printf("  Findings: %d\n", len(findings))
			}
			if run.SarifPath.Valid {
				fmt.Printf("  Output:   %s\n", run.SarifPath.String)
			}
		} else if run.Status == store.RunStatusFailed && run.ErrorMessage.Valid {
			fmt.Printf("  Error:    %s\n", run.ErrorMessage.String)
		}

		return nil
	},
}

func init() {
	importCmd.Flags().String("format", "", "output format override (sarif, semgrep-json)")
	importCmd.Flags().Int64("experiment", 0, "associate with experiment ID")
	importCmd.Flags().Int("iteration", 1, "iteration number")
	importCmd.Flags().String("output-dir", "output", "directory for scan output")
	rootCmd.AddCommand(importCmd)
}
