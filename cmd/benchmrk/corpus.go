package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/block/benchmrk/internal/corpus"
	"github.com/spf13/cobra"
)

var corpusCmd = &cobra.Command{
	Use:   "corpus",
	Short: "Manage corpus projects",
	Long:  "Add, list, show, and remove projects from the benchmark corpus.",
}

var corpusAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a project to the corpus",
	Long:  "Add a new project to the corpus from a local path.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		source, err := cmd.Flags().GetString("source")
		if err != nil {
			return err
		}
		if source == "" {
			return fmt.Errorf("--source flag is required")
		}

		language, err := cmd.Flags().GetString("language")
		if err != nil {
			return fmt.Errorf("get language flag: %w", err)
		}
		commit, err := cmd.Flags().GetString("commit")
		if err != nil {
			return fmt.Errorf("get commit flag: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		project, err := svc.AddProject(ctx, name, source, language, commit)
		if err != nil {
			if errors.Is(err, corpus.ErrEmptyName) {
				return fmt.Errorf("project name cannot be empty")
			}
			if errors.Is(err, corpus.ErrPathNotFound) {
				return fmt.Errorf("source path does not exist: %s", source)
			}
			if errors.Is(err, corpus.ErrDuplicateName) {
				return fmt.Errorf("project with name %q already exists", name)
			}
			return fmt.Errorf("add project: %w", err)
		}

		fmt.Printf("Added project %q (id=%d)\n", project.Name, project.ID)
		if project.Language.Valid {
			fmt.Printf("  Language: %s\n", project.Language.String)
		}
		fmt.Printf("  Path: %s\n", project.LocalPath)

		return nil
	},
}

var corpusListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all corpus projects",
	Long:  "Display all projects in the corpus in a tabular format.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		projects, err := svc.ListProjects(ctx)
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}

		if len(projects) == 0 {
			fmt.Println("No projects in corpus.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tLANGUAGE\tPATH\tCOMMIT")
		for _, p := range projects {
			lang := "-"
			if p.Language.Valid {
				lang = p.Language.String
			}
			commit := "-"
			if p.CommitSHA.Valid {
				commit = p.CommitSHA.String
				if len(commit) > 8 {
					commit = commit[:8]
				}
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", p.ID, p.Name, lang, p.LocalPath, commit)
		}
		w.Flush()

		return nil
	},
}

var corpusShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show project details",
	Long:  "Display detailed information about a corpus project.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		project, err := svc.ShowProject(ctx, name)
		if err != nil {
			if errors.Is(err, corpus.ErrProjectNotFound) {
				return fmt.Errorf("project %q not found", name)
			}
			return fmt.Errorf("show project: %w", err)
		}

		fmt.Printf("Name:       %s\n", project.Name)
		fmt.Printf("ID:         %d\n", project.ID)
		fmt.Printf("Path:       %s\n", project.LocalPath)

		if project.SourceURL.Valid {
			fmt.Printf("Source URL: %s\n", project.SourceURL.String)
		}

		if project.Language.Valid {
			fmt.Printf("Language:   %s\n", project.Language.String)
		} else {
			fmt.Printf("Language:   (not set)\n")
		}

		if project.CommitSHA.Valid {
			fmt.Printf("Commit:     %s\n", project.CommitSHA.String)
		} else {
			fmt.Printf("Commit:     (not set)\n")
		}

		fmt.Printf("Created:    %s\n", project.CreatedAt.Format("2006-01-02 15:04:05"))

		return nil
	},
}

var corpusRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a project from the corpus",
	Long:  "Remove a project from the corpus database. This does not delete files from disk.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		err := svc.RemoveProject(ctx, name)
		if err != nil {
			if errors.Is(err, corpus.ErrProjectNotFound) {
				return fmt.Errorf("project %q not found", name)
			}
			return fmt.Errorf("remove project: %w", err)
		}

		fmt.Printf("Removed project %q\n", name)
		return nil
	},
}

func init() {
	// Add flags
	corpusAddCmd.Flags().StringP("source", "s", "", "source path (local directory)")
	corpusAddCmd.Flags().StringP("language", "l", "", "primary programming language (auto-detected if not specified)")
	corpusAddCmd.Flags().StringP("commit", "c", "", "git commit SHA to pin")

	// Wire up command hierarchy
	corpusCmd.AddCommand(corpusAddCmd)
	corpusCmd.AddCommand(corpusListCmd)
	corpusCmd.AddCommand(corpusShowCmd)
	corpusCmd.AddCommand(corpusRemoveCmd)

	rootCmd.AddCommand(corpusCmd)
}
