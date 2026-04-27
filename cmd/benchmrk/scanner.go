package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/block/benchmrk/internal/scanner"
	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

const adHocExperimentName = "ad-hoc-scans"

var scannerCmd = &cobra.Command{
	Use:   "scanner",
	Short: "Manage scanners",
	Long:  "Register, list, remove, and build scanners for SAST benchmarking.",
}

var scannerRegisterCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register a new scanner",
	Long:  "Register a new scanner with a specified version and Docker image.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		version, err := cmd.Flags().GetString("version")
		if err != nil {
			return err
		}
		if version == "" {
			return fmt.Errorf("--version flag is required")
		}

		mode, err := cmd.Flags().GetString("mode")
		if err != nil {
			return err
		}
		if mode == "" {
			mode = string(store.ExecutionModeDocker)
		}

		image, err := cmd.Flags().GetString("image")
		if err != nil {
			return err
		}

		executable, err := cmd.Flags().GetString("executable")
		if err != nil {
			return err
		}

		switch store.ExecutionMode(mode) {
		case store.ExecutionModeDocker:
			if image == "" {
				return fmt.Errorf("--image flag is required for docker mode")
			}
		case store.ExecutionModeLocal:
			if executable == "" {
				return fmt.Errorf("--executable flag is required for local mode")
			}
		default:
			return fmt.Errorf("invalid mode %q: must be 'docker' or 'local'", mode)
		}

		configJSON, err := cmd.Flags().GetString("config")
		if err != nil {
			return fmt.Errorf("get config flag: %w", err)
		}

		outputFormat, err := cmd.Flags().GetString("output-format")
		if err != nil {
			return fmt.Errorf("get output-format flag: %w", err)
		}

		// If --output-format is set and --config is not, build config from the flag
		if outputFormat != "" && configJSON == "" {
			cfg := scanner.ScannerConfig{OutputFormat: outputFormat}
			data, _ := json.Marshal(cfg)
			configJSON = string(data)
		}

		// Validate config JSON if provided
		if configJSON != "" {
			if _, err := scanner.ParseScannerConfig(configJSON); err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		// Check for duplicate name+version
		existing, err := globalStore.GetScannerByNameVersion(ctx, name, version)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("check existing scanner: %w", err)
		}
		if existing != nil {
			return fmt.Errorf("scanner %s version %s already exists", name, version)
		}

		sc := &store.Scanner{
			Name:          name,
			Version:       version,
			DockerImage:   image,
			ExecutionMode: store.ExecutionMode(mode),
		}
		if executable != "" {
			sc.ExecutablePath = sql.NullString{String: executable, Valid: true}
		}
		if configJSON != "" {
			sc.ConfigJSON = sql.NullString{String: configJSON, Valid: true}
		}

		id, err := globalStore.CreateScanner(ctx, sc)
		if err != nil {
			return fmt.Errorf("create scanner: %w", err)
		}

		fmt.Printf("Registered scanner %q version %q (id=%d)\n", name, version, id)
		fmt.Printf("  Mode: %s\n", mode)
		if store.ExecutionMode(mode) == store.ExecutionModeLocal {
			fmt.Printf("  Executable: %s\n", executable)
		} else {
			fmt.Printf("  Image: %s\n", image)
		}
		if configJSON != "" {
			fmt.Printf("  Config: %s\n", configJSON)
		}

		return nil
	},
}

var scannerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered scanners",
	Long:  "Display all registered scanners in a tabular format.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()
		scanners, err := globalStore.ListScanners(ctx)
		if err != nil {
			return fmt.Errorf("list scanners: %w", err)
		}

		if len(scanners) == 0 {
			fmt.Println("No scanners registered.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tVERSION\tMODE\tIMAGE")
		for _, s := range scanners {
			mode := s.ExecutionMode
			if mode == "" {
				mode = store.ExecutionModeDocker
			}
			image := s.DockerImage
			if mode == store.ExecutionModeLocal && s.ExecutablePath.Valid {
				image = s.ExecutablePath.String
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", s.ID, s.Name, s.Version, mode, image)
		}
		w.Flush()

		return nil
	},
}

var scannerBuildCmd = &cobra.Command{
	Use:   "build <name>",
	Short: "Build a scanner Docker image",
	Long:  "Build a Docker image for the specified scanner from its Dockerfile in scanners/<name>/.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		// Get scanners directory from flag or default
		scannersDir, err := cmd.Flags().GetString("scanners-dir")
		if err != nil {
			return fmt.Errorf("get scanners-dir flag: %w", err)
		}

		// Create Docker runner
		dockerClient, err := scanner.NewRealDockerClient()
		if err != nil {
			return fmt.Errorf("create Docker client: %w", err)
		}

		runner, err := scanner.NewDockerRunner(dockerClient)
		if err != nil {
			return fmt.Errorf("create Docker runner: %w", err)
		}

		svc, err := scanner.NewService(globalStore, runner, scanner.ServiceConfig{
			ScannersDir: scannersDir,
		})
		if err != nil {
			return fmt.Errorf("create scanner service: %w", err)
		}

		ctx := context.Background()

		fmt.Printf("Building scanner image for %q...\n", name)
		if err := svc.Build(ctx, name); err != nil {
			return fmt.Errorf("build scanner: %w", err)
		}

		fmt.Printf("Successfully built image for scanner %q\n", name)
		return nil
	},
}

var scannerRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a registered scanner",
	Long:  "Remove a scanner from the database. This does not delete the Docker image.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		sc, err := globalStore.GetScannerByName(ctx, name)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("scanner %q not found", name)
			}
			return fmt.Errorf("get scanner: %w", err)
		}

		if err := globalStore.DeleteScanner(ctx, sc.ID); err != nil {
			return fmt.Errorf("delete scanner: %w", err)
		}

		fmt.Printf("Removed scanner %q (version %s)\n", sc.Name, sc.Version)
		return nil
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan <scanner> <project>",
	Short: "Run a one-off scan",
	Long:  "Run a scanner against a corpus project and display the results.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		scannerName := args[0]
		projectName := args[1]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		// Get configuration flags
		scannersDir, err := cmd.Flags().GetString("scanners-dir")
		if err != nil {
			return fmt.Errorf("get scanners-dir flag: %w", err)
		}
		outputDir, err := cmd.Flags().GetString("output-dir")
		if err != nil {
			return fmt.Errorf("get output-dir flag: %w", err)
		}
		timeout, err := cmd.Flags().GetInt("timeout")
		if err != nil {
			return fmt.Errorf("get timeout flag: %w", err)
		}
		overrideJSON, err := cmd.Flags().GetString("config-override")
		if err != nil {
			return fmt.Errorf("get config-override flag: %w", err)
		}

		var configOverrides *scanner.ScannerConfig
		if overrideJSON != "" {
			cfg, err := scanner.ParseScannerConfig(overrideJSON)
			if err != nil {
				return fmt.Errorf("invalid config override: %w", err)
			}
			configOverrides = &cfg
		}

		ctx := cmd.Context()

		// Create Docker runner. Only required for Docker-mode scanners —
		// fail early with a clear message instead of a nil-pointer mystery.
		var runner *scanner.DockerRunner
		dockerClient, dockerErr := scanner.NewRealDockerClient()
		if dockerErr == nil {
			runner, _ = scanner.NewDockerRunner(dockerClient)
		} else {
			// Check if the target scanner needs Docker before swallowing the error.
			sc, lookupErr := globalStore.GetScannerByName(ctx, scannerName)
			if lookupErr == nil && (sc.ExecutionMode == store.ExecutionModeDocker || sc.ExecutionMode == "") {
				return fmt.Errorf("scanner %q uses Docker mode but Docker is not available: %w", scannerName, dockerErr)
			}
		}

		svc, err := scanner.NewService(globalStore, runner, scanner.ServiceConfig{
			ScannersDir: scannersDir,
			OutputDir:   outputDir,
		})
		if err != nil {
			return fmt.Errorf("create scanner service: %w", err)
		}

		// Display scan progress
		fmt.Printf("Starting scan: %s → %s\n", scannerName, projectName)

		startTime := time.Now()
		experimentID, err := ensureAdHocExperiment(ctx)
		if err != nil {
			return fmt.Errorf("ensure ad-hoc experiment: %w", err)
		}

		run, err := svc.Scan(ctx, scannerName, projectName, scanner.ScanOptions{
			ExperimentID:    experimentID,
			TimeoutMinutes:  timeout,
			ConfigOverrides: configOverrides,
		})
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		duration := time.Since(startTime)

		// Display results
		fmt.Printf("\nScan complete!\n")
		fmt.Printf("  Status: %s\n", run.Status)
		fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))

		if run.Status == store.RunStatusCompleted {
			// Count findings by querying the store
			findings, err := globalStore.ListFindingsByRun(ctx, run.ID)
			if err != nil {
				fmt.Printf("  Findings: (could not retrieve count)\n")
			} else {
				fmt.Printf("  Findings: %d\n", len(findings))
			}
			if run.SarifPath.Valid {
				fmt.Printf("  SARIF output: %s\n", run.SarifPath.String)
			}
		} else if run.Status == store.RunStatusFailed {
			if run.ErrorMessage.Valid {
				fmt.Printf("  Error: %s\n", run.ErrorMessage.String)
			}
		}

		if run.LogPath.Valid {
			fmt.Printf("  Logs: %s\n", run.LogPath.String)
		}

		return nil
	},
}

func ensureAdHocExperiment(ctx context.Context) (int64, error) {
	e, err := globalStore.GetExperimentByName(ctx, adHocExperimentName)
	if err == nil {
		return e.ID, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return 0, fmt.Errorf("lookup ad-hoc experiment: %w", err)
	}

	id, err := globalStore.CreateExperiment(ctx, &store.Experiment{
		Name:        adHocExperimentName,
		Description: sql.NullString{String: "System-managed experiment for one-off `benchmrk scan` runs", Valid: true},
		Iterations:  1,
	})
	if err != nil {
		return 0, fmt.Errorf("create ad-hoc experiment: %w", err)
	}

	return id, nil
}

func init() {
	// Scanner register flags
	scannerRegisterCmd.Flags().StringP("version", "V", "", "scanner version (required)")
	scannerRegisterCmd.Flags().StringP("image", "i", "", "Docker image (required for docker mode)")
	scannerRegisterCmd.Flags().StringP("mode", "m", "docker", "execution mode (docker or local)")
	scannerRegisterCmd.Flags().StringP("executable", "e", "", "path to local executable (required for local mode)")
	scannerRegisterCmd.Flags().StringP("config", "c", "", "configuration JSON")
	scannerRegisterCmd.Flags().String("output-format", "", "expected output format (sarif, semgrep-json)")

	// Scanner build flags
	scannerBuildCmd.Flags().String("scanners-dir", "scanners", "directory containing scanner Dockerfiles")

	// Scan command flags
	scanCmd.Flags().String("scanners-dir", "scanners", "directory containing scanner Dockerfiles")
	scanCmd.Flags().String("output-dir", "output", "directory for scan output")
	scanCmd.Flags().Int("timeout", 30, "scan timeout in minutes")
	scanCmd.Flags().String("config-override", "", "JSON config overrides for this run")

	// Wire up command hierarchy
	scannerCmd.AddCommand(scannerRegisterCmd)
	scannerCmd.AddCommand(scannerListCmd)
	scannerCmd.AddCommand(scannerRemoveCmd)
	scannerCmd.AddCommand(scannerBuildCmd)

	rootCmd.AddCommand(scannerCmd)
	rootCmd.AddCommand(scanCmd)
}
