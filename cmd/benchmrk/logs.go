package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:   "logs <run-id>",
	Short: "Display scan logs for a run",
	Long:  "Print the captured Docker container stdout/stderr for a scan run.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		runID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid run ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()
		run, err := globalStore.GetRun(ctx, runID)
		if err != nil {
			return fmt.Errorf("get run: %w", err)
		}

		if !run.LogPath.Valid {
			return fmt.Errorf("no logs captured for run %d", runID)
		}

		data, err := os.ReadFile(run.LogPath.String)
		if err != nil {
			return fmt.Errorf("read log file %s: %w", run.LogPath.String, err)
		}

		fmt.Print(string(data))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logsCmd)
}
