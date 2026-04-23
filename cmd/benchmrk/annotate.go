package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/block/benchmrk/internal/corpus"
	"github.com/spf13/cobra"
)

var annotateCmd = &cobra.Command{
	Use:   "annotate",
	Short: "Manage ground-truth annotations",
	Long:  "Add, list, import, and export ground-truth vulnerability annotations.",
}

var annotateAddCmd = &cobra.Command{
	Use:   "add <project>",
	Short: "Add an annotation to a project",
	Long:  "Add a ground-truth vulnerability annotation to a corpus project.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}
		if filePath == "" {
			return fmt.Errorf("--file flag is required")
		}

		line, err := cmd.Flags().GetInt("line")
		if err != nil {
			return err
		}
		if line <= 0 {
			return fmt.Errorf("--line must be a positive integer")
		}

		cweID, err := cmd.Flags().GetString("cwe")
		if err != nil {
			return err
		}
		if cweID == "" {
			return fmt.Errorf("--cwe flag is required")
		}

		category, err := cmd.Flags().GetString("category")
		if err != nil {
			return err
		}
		if category == "" {
			return fmt.Errorf("--category flag is required")
		}

		severity, err := cmd.Flags().GetString("severity")
		if err != nil {
			return err
		}
		if severity == "" {
			return fmt.Errorf("--severity flag is required")
		}

		description, err := cmd.Flags().GetString("description")
		if err != nil {
			return err
		}

		endLine, err := cmd.Flags().GetInt("end-line")
		if err != nil {
			return err
		}
		var endLinePtr *int
		if endLine > 0 {
			if endLine < line {
				return fmt.Errorf("--end-line must be >= --line")
			}
			endLinePtr = &endLine
		}

		status, err := cmd.Flags().GetString("status")
		if err != nil {
			return err
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		annotation, err := svc.AddAnnotation(ctx, projectName, filePath, line, endLinePtr, cweID, category, severity, description, status)
		if err != nil {
			if errors.Is(err, corpus.ErrProjectNotFound) {
				return fmt.Errorf("project %q not found", projectName)
			}
			if errors.Is(err, corpus.ErrInvalidSeverity) {
				return fmt.Errorf("invalid severity %q: must be one of critical, high, medium, low, info", severity)
			}
			return fmt.Errorf("add annotation: %w", err)
		}

		fmt.Printf("Added annotation (id=%d)\n", annotation.ID)
		fmt.Printf("  File:     %s:%d\n", annotation.FilePath, annotation.StartLine)
		fmt.Printf("  CWE:      %s\n", cweID)
		fmt.Printf("  Category: %s\n", annotation.Category)
		fmt.Printf("  Severity: %s\n", annotation.Severity)
		fmt.Printf("  Status:   %s\n", annotation.Status)

		return nil
	},
}

var annotateListCmd = &cobra.Command{
	Use:   "list <project>",
	Short: "List annotations for a project",
	Long:  "Display all ground-truth annotations for a corpus project in tabular format.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		annotations, err := svc.ListAnnotations(ctx, projectName)
		if err != nil {
			if errors.Is(err, corpus.ErrProjectNotFound) {
				return fmt.Errorf("project %q not found", projectName)
			}
			return fmt.Errorf("list annotations: %w", err)
		}

		if len(annotations) == 0 {
			fmt.Println("No annotations for this project.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tFILE\tLINE\tCWE\tCATEGORY\tSEVERITY\tSTATUS")
		for _, a := range annotations {
			cwe := "-"
			if a.CWEID.Valid {
				cwe = a.CWEID.String
			}
			lineStr := fmt.Sprintf("%d", a.StartLine)
			if a.EndLine.Valid {
				lineStr = fmt.Sprintf("%d-%d", a.StartLine, a.EndLine.Int64)
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.FilePath, lineStr, cwe, a.Category, a.Severity, a.Status)
		}
		w.Flush()

		return nil
	},
}

var annotateImportCmd = &cobra.Command{
	Use:   "import <project>",
	Short: "Import annotations from JSON file",
	Long:  "Bulk import ground-truth annotations from a JSON file.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]

		filePath, err := cmd.Flags().GetString("file")
		if err != nil {
			return err
		}
		if filePath == "" {
			return fmt.Errorf("--file flag is required")
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		replace, err := cmd.Flags().GetBool("replace")
		if err != nil {
			return err
		}

		if verbose {
			fmt.Printf("Reading annotations from %s...\n", filePath)
		}

		if replace && verbose {
			fmt.Println("Replacing existing annotations...")
		}

		count, err := svc.ImportAnnotations(ctx, projectName, filePath, replace)
		if err != nil {
			if errors.Is(err, corpus.ErrProjectNotFound) {
				return fmt.Errorf("project %q not found (use 'benchmrk corpus list' to see available projects)", projectName)
			}
			if errors.Is(err, corpus.ErrInvalidSeverity) {
				return fmt.Errorf("import failed: %w (valid values: critical, high, medium, low, info)", err)
			}
			return fmt.Errorf("import annotations: %w", err)
		}

		fmt.Printf("Imported %d annotations into project %q\n", count, projectName)
		return nil
	},
}

var annotateExportCmd = &cobra.Command{
	Use:   "export <project>",
	Short: "Export annotations to JSON",
	Long:  "Export all ground-truth annotations for a project as JSON to stdout.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		data, err := svc.ExportAnnotations(ctx, projectName)
		if err != nil {
			if errors.Is(err, corpus.ErrProjectNotFound) {
				return fmt.Errorf("project %q not found", projectName)
			}
			return fmt.Errorf("export annotations: %w", err)
		}

		fmt.Println(string(data))
		return nil
	},
}

var annotateUpdateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update an existing annotation",
	Long:  "Update fields of an existing annotation by ID. Only specified flags are changed.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid annotation ID %q", args[0])
		}

		filePath, _ := cmd.Flags().GetString("file")
		line, _ := cmd.Flags().GetInt("line")
		cweID, _ := cmd.Flags().GetString("cwe")
		category, _ := cmd.Flags().GetString("category")
		severity, _ := cmd.Flags().GetString("severity")
		description, _ := cmd.Flags().GetString("description")
		status, _ := cmd.Flags().GetString("status")
		endLine, _ := cmd.Flags().GetInt("end-line")

		var endLinePtr *int
		if cmd.Flags().Changed("end-line") {
			endLinePtr = &endLine
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		annotation, err := svc.UpdateAnnotation(ctx, id, filePath, line, endLinePtr, cweID, category, severity, description, status)
		if err != nil {
			return fmt.Errorf("update annotation: %w", err)
		}

		cwe := "-"
		if annotation.CWEID.Valid {
			cwe = annotation.CWEID.String
		}
		fmt.Printf("Updated annotation %d\n", annotation.ID)
		fmt.Printf("  File:     %s:%d\n", annotation.FilePath, annotation.StartLine)
		fmt.Printf("  CWE:      %s\n", cwe)
		fmt.Printf("  Category: %s\n", annotation.Category)
		fmt.Printf("  Severity: %s\n", annotation.Severity)
		fmt.Printf("  Status:   %s\n", annotation.Status)

		return nil
	},
}

var annotateHistoryCmd = &cobra.Command{
	Use:   "history <project>",
	Short: "Show annotation set import history",
	Long: "List every annotation import for a project, with hash, source file, " +
		"git SHA, and vuln count. The hash column matches runs.annotation_hash, " +
		"so you can trace a run's scorer stamp back to the import that produced it.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		project, err := globalStore.GetProjectByName(ctx, args[0])
		if err != nil {
			return fmt.Errorf("project %q not found: %w", args[0], err)
		}

		sets, err := globalStore.ListAnnotationSetsByProject(ctx, project.ID)
		if err != nil {
			return fmt.Errorf("list annotation sets: %w", err)
		}
		if len(sets) == 0 {
			fmt.Println("No recorded imports. Annotation set history starts " +
				"with the first import after migration 011.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "HASH\tVULNS\tGIT SHA\tSOURCE\tIMPORTED")
		for _, s := range sets {
			sha := "-"
			if s.GitSHA.Valid {
				sha = s.GitSHA.String[:min(12, len(s.GitSHA.String))]
			}
			src := "-"
			if s.SourcePath.Valid {
				src = s.SourcePath.String
			}
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n",
				s.Hash, s.VulnCount, sha, src,
				s.ImportedAt.Format("2006-01-02 15:04"))
		}
		w.Flush()
		return nil
	},
}

var annotateDiffCmd = &cobra.Command{
	Use:   "diff <hash-a> <hash-b>",
	Short: "Explain the difference between two annotation set hashes",
	Long: "Given two annotation_hash values (from runs.annotation_hash or " +
		"'annotate history'), show what's known about each and how to see " +
		"the actual diff.\n\n" +
		"benchmrk doesn't snapshot annotation content — it records the " +
		"source file and git SHA at import time. The real diff is in git; " +
		"this command tells you which commits to compare.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		describe := func(hash string) {
			fmt.Printf("  %s", hash)
			set, err := globalStore.GetAnnotationSetByHash(ctx, hash)
			if err != nil {
				fmt.Printf("  (no import record — scored before migration 011, " +
					"or annotations were edited in-place via the API)\n")
				return
			}
			fmt.Printf("  %d vulns, %s format", set.VulnCount, set.Format)
			if set.GitSHA.Valid {
				fmt.Printf(", git %s", set.GitSHA.String[:min(12, len(set.GitSHA.String))])
			}
			if set.SourcePath.Valid {
				fmt.Printf(", %s", set.SourcePath.String)
			}
			fmt.Printf(", imported %s\n", set.ImportedAt.Format("2006-01-02 15:04"))
		}

		fmt.Println("Annotation set A:")
		describe(args[0])
		fmt.Println("Annotation set B:")
		describe(args[1])

		a, errA := globalStore.GetAnnotationSetByHash(ctx, args[0])
		b, errB := globalStore.GetAnnotationSetByHash(ctx, args[1])
		if errA == nil && errB == nil &&
			a.GitSHA.Valid && b.GitSHA.Valid && a.SourcePath.Valid && b.SourcePath.Valid {
			// Same file at different commits is the interesting case.
			// Different files: just show both, let the user figure it out.
			if a.SourcePath.String == b.SourcePath.String {
				fmt.Printf("\nTo see the content diff:\n")
				fmt.Printf("  git diff %s %s -- %s\n",
					a.GitSHA.String[:12], b.GitSHA.String[:12], a.SourcePath.String)
			} else {
				fmt.Printf("\nDifferent source files — compare manually:\n")
				fmt.Printf("  git show %s:%s\n", a.GitSHA.String[:12], a.SourcePath.String)
				fmt.Printf("  git show %s:%s\n", b.GitSHA.String[:12], b.SourcePath.String)
			}
		}
		return nil
	},
}

var annotateDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete an annotation",
	Long:  "Delete a ground-truth annotation by ID.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid annotation ID %q", args[0])
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		svc := corpus.New(globalStore)
		ctx := context.Background()

		if err := svc.DeleteAnnotation(ctx, id); err != nil {
			return fmt.Errorf("delete annotation: %w", err)
		}

		fmt.Printf("Deleted annotation %d\n", id)
		return nil
	},
}

func init() {
	// Add flags
	annotateAddCmd.Flags().StringP("file", "f", "", "file path within project (required)")
	annotateAddCmd.Flags().IntP("line", "l", 0, "start line number (required)")
	annotateAddCmd.Flags().Int("end-line", 0, "end line number (optional)")
	annotateAddCmd.Flags().StringP("cwe", "w", "", "CWE ID (required)")
	annotateAddCmd.Flags().StringP("category", "c", "", "vulnerability category (required)")
	annotateAddCmd.Flags().StringP("severity", "s", "", "severity: critical, high, medium, low, info (required)")
	annotateAddCmd.Flags().StringP("description", "d", "", "description (optional)")
	annotateAddCmd.Flags().String("status", "valid", "annotation validity: valid, invalid, disputed")

	annotateUpdateCmd.Flags().StringP("file", "f", "", "file path within project")
	annotateUpdateCmd.Flags().IntP("line", "l", 0, "start line number")
	annotateUpdateCmd.Flags().Int("end-line", 0, "end line number")
	annotateUpdateCmd.Flags().StringP("cwe", "w", "", "CWE ID")
	annotateUpdateCmd.Flags().StringP("category", "c", "", "vulnerability category")
	annotateUpdateCmd.Flags().StringP("severity", "s", "", "severity: critical, high, medium, low, info")
	annotateUpdateCmd.Flags().StringP("description", "d", "", "description")
	annotateUpdateCmd.Flags().String("status", "", "annotation validity: valid, invalid, disputed")

	annotateImportCmd.Flags().StringP("file", "f", "", "path to JSON file (required)")
	annotateImportCmd.Flags().Bool("replace", false, "delete all existing annotations before importing")

	// Wire up command hierarchy
	annotateCmd.AddCommand(annotateAddCmd)
	annotateCmd.AddCommand(annotateListCmd)
	annotateCmd.AddCommand(annotateImportCmd)
	annotateCmd.AddCommand(annotateExportCmd)
	annotateCmd.AddCommand(annotateUpdateCmd)
	annotateCmd.AddCommand(annotateDeleteCmd)
	annotateCmd.AddCommand(annotateHistoryCmd)
	annotateCmd.AddCommand(annotateDiffCmd)

	rootCmd.AddCommand(annotateCmd)
}
