package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/experiment"
	"github.com/block/benchmrk/internal/scanner"
	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

// initScannerService creates a scanner service, optionally with Docker support.
// Local-mode scanners work even when Docker is unavailable — only Docker-mode
// scanners will fail at scan time if the runner is nil.
func initScannerService(outputDir string) *scanner.Service {
	var dockerRunner *scanner.DockerRunner
	dockerClient, err := scanner.NewRealDockerClient()
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: Docker not available: %v (local scanners still work)\n", err)
		}
	} else {
		dockerRunner, err = scanner.NewDockerRunner(dockerClient)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "Warning: Failed to create Docker runner: %v\n", err)
			}
		} else if verbose {
			dockerRunner.SetLogWriter(os.Stderr)
		}
	}

	scannerSvc, err := scanner.NewService(globalStore, dockerRunner, scanner.ServiceConfig{
		ScannersDir: "scanners",
		OutputDir:   outputDir,
	})
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create scanner service: %v\n", err)
		}
		return nil
	}

	return scannerSvc
}

var experimentCmd = &cobra.Command{
	Use:   "experiment",
	Short: "Manage experiments",
	Long:  "Create, run, and manage benchmarking experiments.",
}

var experimentCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new experiment",
	Long:  "Create a new experiment with specified scanners and projects.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		description, err := cmd.Flags().GetString("description")
		if err != nil {
			return fmt.Errorf("get description flag: %w", err)
		}

		scannersStr, err := cmd.Flags().GetString("scanners")
		if err != nil {
			return fmt.Errorf("get scanners flag: %w", err)
		}
		if scannersStr == "" {
			return fmt.Errorf("--scanners flag is required")
		}

		projectsStr, err := cmd.Flags().GetString("projects")
		if err != nil {
			return fmt.Errorf("get projects flag: %w", err)
		}
		if projectsStr == "" {
			return fmt.Errorf("--projects flag is required")
		}

		iterations, err := cmd.Flags().GetInt("iterations")
		if err != nil {
			return fmt.Errorf("get iterations flag: %w", err)
		}
		if iterations <= 0 {
			return fmt.Errorf("iterations must be positive")
		}

		scannerIDs, err := parseIDList(scannersStr)
		if err != nil {
			return fmt.Errorf("parse scanner IDs: %w", err)
		}

		projectIDs, err := parseIDList(projectsStr)
		if err != nil {
			return fmt.Errorf("parse project IDs: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc, err := experiment.NewService(globalStore, nil, nil)
		if err != nil {
			return fmt.Errorf("create experiment service: %w", err)
		}

		ctx := context.Background()
		exp, err := svc.Create(ctx, name, description, scannerIDs, projectIDs, iterations)
		if err != nil {
			return fmt.Errorf("create experiment: %w", err)
		}

		fmt.Printf("Created experiment %q (id=%d)\n", exp.Name, exp.ID)
		fmt.Printf("  Iterations: %d\n", exp.Iterations)
		fmt.Printf("  Scanners: %d\n", len(scannerIDs))
		fmt.Printf("  Projects: %d\n", len(projectIDs))
		fmt.Printf("  Total runs: %d\n", len(scannerIDs)*len(projectIDs)*iterations)

		return nil
	},
}

var experimentListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all experiments",
	Long:  "Display all experiments in a tabular format.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()
		experiments, err := globalStore.ListExperiments(ctx)
		if err != nil {
			return fmt.Errorf("list experiments: %w", err)
		}

		if len(experiments) == 0 {
			fmt.Println("No experiments.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tITERATIONS\tCREATED")
		for _, e := range experiments {
			fmt.Fprintf(w, "%d\t%s\t%d\t%s\n", e.ID, e.Name, e.Iterations, e.CreatedAt.Format("2006-01-02"))
		}
		w.Flush()

		return nil
	},
}

var experimentShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show experiment details",
	Long:  "Display detailed information about an experiment.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		exp, err := globalStore.GetExperiment(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("experiment %d not found", id)
			}
			return fmt.Errorf("get experiment: %w", err)
		}

		fmt.Printf("Name:        %s\n", exp.Name)
		fmt.Printf("ID:          %d\n", exp.ID)
		if exp.Description.Valid {
			fmt.Printf("Description: %s\n", exp.Description.String)
		}
		fmt.Printf("Iterations:  %d\n", exp.Iterations)
		fmt.Printf("Created:     %s\n", exp.CreatedAt.Format("2006-01-02 15:04:05"))

		scanners, err := globalStore.ListExperimentScanners(ctx, id)
		if err != nil {
			return fmt.Errorf("list scanners: %w", err)
		}
		fmt.Printf("\nScanners (%d):\n", len(scanners))
		for _, sc := range scanners {
			fmt.Printf("  - %s v%s (id=%d)\n", sc.Name, sc.Version, sc.ID)
		}

		projects, err := globalStore.ListExperimentProjects(ctx, id)
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}
		fmt.Printf("\nProjects (%d):\n", len(projects))
		for _, p := range projects {
			fmt.Printf("  - %s (id=%d)\n", p.Name, p.ID)
		}

		runs, err := globalStore.ListRunsByExperiment(ctx, id)
		if err != nil {
			return fmt.Errorf("list runs: %w", err)
		}
		fmt.Printf("\nRuns (%d total):\n", len(runs))
		statusCounts := make(map[store.RunStatus]int)
		for _, r := range runs {
			statusCounts[r.Status]++
		}
		for status, count := range statusCounts {
			fmt.Printf("  - %s: %d\n", status, count)
		}

		return nil
	},
}

var experimentRunCmd = &cobra.Command{
	Use:   "run <id>",
	Short: "Execute an experiment",
	Long:  "Run all scanner×project combinations for an experiment.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		concurrency, err := cmd.Flags().GetInt("concurrency")
		if err != nil {
			return fmt.Errorf("get concurrency flag: %w", err)
		}

		reuse, _ := cmd.Flags().GetBool("reuse")

		outputDir, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return fmt.Errorf("get output-dir flag: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		// Initialize scanner service — works for local scanners even without Docker.
		scannerSvc := initScannerService(outputDir)
		if scannerSvc == nil {
			return fmt.Errorf("failed to initialize scanner service (run with --verbose for details)")
		}

		analysisSvc := analysis.NewService(globalStore, nil)
		svc, err := experiment.NewService(globalStore, scannerSvc, analysisSvc)
		if err != nil {
			return fmt.Errorf("create experiment service: %w", err)
		}

		ctx := context.Background()

		exp, err := globalStore.GetExperiment(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("experiment %d not found", id)
			}
			return fmt.Errorf("get experiment: %w", err)
		}

		// Get total run count for progress display
		runs, err := globalStore.ListRunsByExperiment(ctx, id)
		if err != nil {
			return fmt.Errorf("list runs: %w", err)
		}
		totalRuns := len(runs)

		fmt.Printf("Executing experiment %q (id=%d) with concurrency=%d", exp.Name, exp.ID, concurrency)
		if reuse {
			fmt.Printf(" [reuse enabled]")
		}
		fmt.Printf("...\n")
		fmt.Printf("Total runs: %d\n\n", totalRuns)

		// Set up progress callback
		svc.SetProgressCallback(func(completed, total int, scanner, project, status string) {
			statusIcon := "✓"
			if status == string(store.RunStatusFailed) {
				statusIcon = "✗"
			}
			fmt.Printf("[%d/%d] %s %s × %s: %s\n", completed, total, statusIcon, scanner, project, status)
		})

		if err := svc.Execute(ctx, id, experiment.ExecuteOptions{Concurrency: concurrency, ReuseRuns: reuse}); err != nil {
			return fmt.Errorf("execute experiment: %w", err)
		}

		expStatus, err := svc.Status(ctx, id)
		if err != nil {
			return fmt.Errorf("get status: %w", err)
		}

		fmt.Printf("\nExecution complete!\n")
		fmt.Printf("  Completed: %d\n", expStatus.Completed)
		fmt.Printf("  Failed:    %d\n", expStatus.Failed)
		fmt.Printf("  Pending:   %d\n", expStatus.Pending)

		return nil
	},
}

var experimentResumeCmd = &cobra.Command{
	Use:   "resume <id>",
	Short: "Resume a partially-completed experiment",
	Long:  "Retry pending and failed runs for an experiment.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		concurrency, err := cmd.Flags().GetInt("concurrency")
		if err != nil {
			return fmt.Errorf("get concurrency flag: %w", err)
		}

		reuse, _ := cmd.Flags().GetBool("reuse")

		outputDir, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return fmt.Errorf("get output-dir flag: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		// Initialize scanner service — works for local scanners even without Docker.
		scannerSvc := initScannerService(outputDir)
		if scannerSvc == nil {
			return fmt.Errorf("failed to initialize scanner service (run with --verbose for details)")
		}

		analysisSvc := analysis.NewService(globalStore, nil)
		svc, err := experiment.NewService(globalStore, scannerSvc, analysisSvc)
		if err != nil {
			return fmt.Errorf("create experiment service: %w", err)
		}

		ctx := context.Background()

		exp, err := globalStore.GetExperiment(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("experiment %d not found", id)
			}
			return fmt.Errorf("get experiment: %w", err)
		}

		// Count pending/failed runs for progress display
		currentStatus, err := svc.Status(ctx, id)
		if err != nil {
			return fmt.Errorf("get status: %w", err)
		}
		pendingRuns := currentStatus.Pending + currentStatus.Failed

		fmt.Printf("Resuming experiment %q (id=%d) with concurrency=%d", exp.Name, exp.ID, concurrency)
		if reuse {
			fmt.Printf(" [reuse enabled]")
		}
		fmt.Printf("...\n")
		fmt.Printf("Runs to retry: %d\n\n", pendingRuns)

		// Set up progress callback
		svc.SetProgressCallback(func(completed, total int, scanner, project, status string) {
			statusIcon := "✓"
			if status == string(store.RunStatusFailed) {
				statusIcon = "✗"
			}
			fmt.Printf("[%d/%d] %s %s × %s: %s\n", completed, total, statusIcon, scanner, project, status)
		})

		if err := svc.Resume(ctx, id, experiment.ExecuteOptions{Concurrency: concurrency, ReuseRuns: reuse}); err != nil {
			return fmt.Errorf("resume experiment: %w", err)
		}

		expStatus, err := svc.Status(ctx, id)
		if err != nil {
			return fmt.Errorf("get status: %w", err)
		}

		fmt.Printf("\nResume complete!\n")
		fmt.Printf("  Completed: %d\n", expStatus.Completed)
		fmt.Printf("  Failed:    %d\n", expStatus.Failed)
		fmt.Printf("  Pending:   %d\n", expStatus.Pending)

		return nil
	},
}

var experimentStatusCmd = &cobra.Command{
	Use:   "status <id>",
	Short: "Show run status breakdown",
	Long:  "Display pending/running/completed/failed run counts for an experiment.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc, err := experiment.NewService(globalStore, nil, nil)
		if err != nil {
			return fmt.Errorf("create experiment service: %w", err)
		}

		ctx := context.Background()

		status, err := svc.Status(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("experiment %d not found", id)
			}
			return fmt.Errorf("get status: %w", err)
		}

		fmt.Printf("Experiment: %s (id=%d)\n", status.Name, status.ExperimentID)
		fmt.Printf("Total runs: %d\n\n", status.TotalRuns)
		fmt.Printf("  Pending:   %d\n", status.Pending)
		fmt.Printf("  Running:   %d\n", status.Running)
		fmt.Printf("  Completed: %d\n", status.Completed)
		fmt.Printf("  Failed:    %d\n", status.Failed)

		if status.TotalRuns > 0 {
			pct := float64(status.Completed) / float64(status.TotalRuns) * 100
			fmt.Printf("\nProgress: %.1f%% complete\n", pct)
		}

		return nil
	},
}

var experimentResultsCmd = &cobra.Command{
	Use:   "results <id>",
	Short: "Show experiment results",
	Long:  "Display summary metrics table (scanner × project).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		exp, err := globalStore.GetExperiment(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("experiment %d not found", id)
			}
			return fmt.Errorf("get experiment: %w", err)
		}

		scanners, err := globalStore.ListExperimentScanners(ctx, id)
		if err != nil {
			return fmt.Errorf("list scanners: %w", err)
		}

		projects, err := globalStore.ListExperimentProjects(ctx, id)
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}

		runs, err := globalStore.ListRunsByExperiment(ctx, id)
		if err != nil {
			return fmt.Errorf("list runs: %w", err)
		}

		fmt.Printf("Experiment: %s (id=%d)\n\n", exp.Name, exp.ID)

		if len(scanners) == 0 || len(projects) == 0 {
			fmt.Println("No scanners or projects in experiment.")
			return nil
		}

		type runInfo struct {
			Status       store.RunStatus
			ErrorMessage string
			LogPath      string
		}
		runStatus := make(map[int64]map[int64]runInfo)
		for _, r := range runs {
			if runStatus[r.ScannerID] == nil {
				runStatus[r.ScannerID] = make(map[int64]runInfo)
			}
			existing := runStatus[r.ScannerID][r.ProjectID]
			if existing.Status == "" || r.Status == store.RunStatusCompleted {
				info := runInfo{Status: r.Status}
				if r.ErrorMessage.Valid {
					info.ErrorMessage = r.ErrorMessage.String
				}
				if r.LogPath.Valid {
					info.LogPath = r.LogPath.String
				}
				runStatus[r.ScannerID][r.ProjectID] = info
			}
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		header := "SCANNER"
		for _, p := range projects {
			header += "\t" + p.Name
		}
		fmt.Fprintln(w, header)

		type failedRun struct {
			Scanner string
			Project string
			Error   string
			LogPath string
		}
		var failedRuns []failedRun

		for _, sc := range scanners {
			row := sc.Name
			for _, p := range projects {
				info := runStatus[sc.ID][p.ID]
				status := string(info.Status)
				if status == "" {
					status = "-"
				}
				row += "\t" + status
				if info.Status == store.RunStatusFailed && info.ErrorMessage != "" {
					failedRuns = append(failedRuns, failedRun{
						Scanner: sc.Name,
						Project: p.Name,
						Error:   info.ErrorMessage,
						LogPath: info.LogPath,
					})
				}
			}
			fmt.Fprintln(w, row)
		}
		w.Flush()

		if len(failedRuns) > 0 {
			fmt.Printf("\nFailed Runs (%d):\n", len(failedRuns))
			for _, f := range failedRuns {
				fmt.Printf("  • %s × %s:\n    %s\n", f.Scanner, f.Project, f.Error)
				if f.LogPath != "" {
					fmt.Printf("    Logs: %s\n", f.LogPath)
				}
			}
		}

		return nil
	},
}

var experimentDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete an experiment",
	Long:  "Remove an experiment and all associated data.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		exp, err := globalStore.GetExperiment(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("experiment %d not found", id)
			}
			return fmt.Errorf("get experiment: %w", err)
		}

		if err := globalStore.DeleteExperiment(ctx, id); err != nil {
			return fmt.Errorf("delete experiment: %w", err)
		}

		fmt.Printf("Deleted experiment %q (id=%d)\n", exp.Name, id)
		return nil
	},
}

func parseIDList(s string) ([]int64, error) {
	parts := strings.Split(s, ",")
	ids := make([]int64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid ID %q: %w", p, err)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no valid IDs provided")
	}
	return ids, nil
}

func init() {
	experimentCreateCmd.Flags().StringP("description", "d", "", "experiment description")
	experimentCreateCmd.Flags().StringP("scanners", "s", "", "comma-separated scanner IDs (required)")
	experimentCreateCmd.Flags().StringP("projects", "p", "", "comma-separated project IDs (required)")
	experimentCreateCmd.Flags().IntP("iterations", "i", 1, "number of iterations per scanner×project")

	experimentRunCmd.Flags().IntP("concurrency", "c", 2, "number of concurrent runs")
	experimentRunCmd.Flags().Bool("reuse", false, "reuse results from prior completed runs instead of re-executing")
	experimentRunCmd.Flags().String("output-dir", "output", "directory for scan output")
	experimentResumeCmd.Flags().IntP("concurrency", "c", 2, "number of concurrent runs")
	experimentResumeCmd.Flags().Bool("reuse", false, "reuse results from prior completed runs instead of re-executing")
	experimentResumeCmd.Flags().String("output-dir", "output", "directory for scan output")

	experimentCmd.AddCommand(experimentCreateCmd)
	experimentCmd.AddCommand(experimentListCmd)
	experimentCmd.AddCommand(experimentShowCmd)
	experimentCmd.AddCommand(experimentRunCmd)
	experimentCmd.AddCommand(experimentResumeCmd)
	experimentCmd.AddCommand(experimentStatusCmd)
	experimentCmd.AddCommand(experimentResultsCmd)
	experimentCmd.AddCommand(experimentDeleteCmd)

	rootCmd.AddCommand(experimentCmd)
}
