package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

var (
	version          = "0.1.0"
	dbPath           string
	verbose          bool
	globalStore      *store.Store
	storeInitialized bool // tracks if store was initialized by PersistentPreRunE
)

var rootCmd = &cobra.Command{
	Use:     "benchmrk",
	Short:   "SAST benchmarking tool",
	Long:    "benchmrk is a tool for objectively measuring the efficacy of static analysis scanners.",
	Version: version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip store initialization for help and version commands
		if cmd.Name() == "help" || cmd.Name() == "__complete" || cmd.Name() == "__completeNoDesc" {
			return nil
		}

		// Skip if store is already initialized (e.g., in tests)
		if globalStore != nil {
			return nil
		}

		// Expand ~ in path
		expandedPath := dbPath
		if len(dbPath) > 0 && dbPath[0] == '~' {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("get home directory: %w", err)
			}
			expandedPath = filepath.Join(home, dbPath[1:])
		}

		// Ensure parent directory exists
		dir := filepath.Dir(expandedPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create database directory: %w", err)
		}

		// Initialize store
		s, err := store.New(expandedPath)
		if err != nil {
			return fmt.Errorf("initialize store: %w", err)
		}
		globalStore = s
		storeInitialized = true

		if verbose {
			fmt.Fprintf(os.Stderr, "Using database: %s\n", expandedPath)
		}

		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		// Only close if we initialized the store (not in tests)
		if globalStore != nil && storeInitialized {
			storeInitialized = false
			err := globalStore.Close()
			globalStore = nil
			return err
		}
		return nil
	},
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Long:  "Apply all pending database migrations to create or update the schema.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		if verbose {
			fmt.Println("Running database migrations...")
		}

		if err := globalStore.Migrate(); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}

		fmt.Println("Migrations applied successfully")
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", "~/.benchmrk/benchmrk.db", "database file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.AddCommand(migrateCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
