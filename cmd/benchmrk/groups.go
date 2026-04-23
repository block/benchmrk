package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/block/benchmrk/internal/store"
	"github.com/spf13/cobra"
)

// Migration 010 folded groups into the vulnerability model: a "group"
// is now a vulnerability with >1 evidence row. CreateAnnotationGroup
// and DeleteAnnotationGroup return errGroupsMigrated unconditionally,
// so these two commands always fail. Kept (hidden) so old scripts get
// the migration-pointer error instead of "unknown command".
var annotateGroupCmd = &cobra.Command{
	Use:    "group <project>",
	Short:  "Create an annotation group (deprecated — see migration 010)",
	Long:   "Deprecated. Groups were folded into the vulnerability model; add evidence rows to an existing vulnerability instead.",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]

		annotationIDs, err := cmd.Flags().GetString("annotations")
		if err != nil {
			return err
		}
		if annotationIDs == "" {
			return fmt.Errorf("--annotations flag is required (comma-separated annotation IDs)")
		}

		groupName, _ := cmd.Flags().GetString("name")

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		// Lookup project
		project, err := globalStore.GetProjectByName(ctx, projectName)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("project %q not found", projectName)
			}
			return fmt.Errorf("get project: %w", err)
		}

		// Parse annotation IDs
		idStrs := strings.Split(annotationIDs, ",")
		if len(idStrs) < 2 {
			return fmt.Errorf("at least 2 annotation IDs required for a group")
		}

		var ids []int64
		for _, s := range idStrs {
			s = strings.TrimSpace(s)
			id, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid annotation ID %q: %w", s, err)
			}
			ids = append(ids, id)
		}

		// Verify all annotations exist and belong to this project
		for _, id := range ids {
			ann, err := globalStore.GetAnnotation(ctx, id)
			if err != nil {
				return fmt.Errorf("annotation %d not found: %w", id, err)
			}
			if ann.ProjectID != project.ID {
				return fmt.Errorf("annotation %d does not belong to project %q", id, projectName)
			}
		}

		// Create the group
		g := &store.AnnotationGroup{
			ProjectID: project.ID,
		}
		if groupName != "" {
			g.Name = sql.NullString{String: groupName, Valid: true}
		}

		groupID, err := globalStore.CreateAnnotationGroup(ctx, g)
		if err != nil {
			return fmt.Errorf("create group: %w", err)
		}

		// Add members
		for _, id := range ids {
			if err := globalStore.AddAnnotationToGroup(ctx, groupID, id, "related"); err != nil {
				return fmt.Errorf("add annotation %d to group: %w", id, err)
			}
		}

		name := fmt.Sprintf("%d", groupID)
		if groupName != "" {
			name = fmt.Sprintf("%q (id=%d)", groupName, groupID)
		}
		fmt.Printf("Created annotation group %s with %d members\n", name, len(ids))

		return nil
	},
}

var annotateGroupsCmd = &cobra.Command{
	Use:   "groups <project>",
	Short: "List annotation groups",
	Long:  "Display all annotation groups for a project with their members.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectName := args[0]

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()

		project, err := globalStore.GetProjectByName(ctx, projectName)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("project %q not found", projectName)
			}
			return fmt.Errorf("get project: %w", err)
		}

		groups, err := globalStore.ListAnnotationGroupsByProject(ctx, project.ID)
		if err != nil {
			return fmt.Errorf("list groups: %w", err)
		}

		if len(groups) == 0 {
			fmt.Println("No annotation groups for this project.")
			return nil
		}

		for _, g := range groups {
			name := "(unnamed)"
			if g.Name.Valid && g.Name.String != "" {
				name = g.Name.String
			}
			fmt.Printf("Group %d: %s\n", g.ID, name)

			members, err := globalStore.ListGroupMembers(ctx, g.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  (error loading members: %v)\n", err)
				continue
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  ANNOTATION\tFILE\tLINE\tCWE\tCATEGORY\tROLE")
			for _, m := range members {
				ann, err := globalStore.GetAnnotation(ctx, m.AnnotationID)
				if err != nil {
					fmt.Fprintf(w, "  %d\t(not found)\t\t\t\t%s\n", m.AnnotationID, m.Role)
					continue
				}
				cwe := ""
				if ann.CWEID.Valid {
					cwe = ann.CWEID.String
				}
				fmt.Fprintf(w, "  %d\t%s\t%d\t%s\t%s\t%s\n",
					ann.ID, ann.FilePath, ann.StartLine, cwe, ann.Category, m.Role)
			}
			w.Flush()
			fmt.Println()
		}

		return nil
	},
}

var annotateUngroupCmd = &cobra.Command{
	Use:    "ungroup <group-id>",
	Short:  "Delete an annotation group (deprecated — see migration 010)",
	Long:   "Deprecated. Groups were folded into the vulnerability model; delete the evidence row or the vulnerability directly.",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		groupID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid group ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		ctx := context.Background()
		if err := globalStore.DeleteAnnotationGroup(ctx, groupID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("group %d not found", groupID)
			}
			return fmt.Errorf("delete group: %w", err)
		}

		fmt.Printf("Deleted annotation group %d\n", groupID)
		return nil
	},
}

func init() {
	annotateGroupCmd.Flags().String("annotations", "", "comma-separated annotation IDs to group (required)")
	annotateGroupCmd.Flags().String("name", "", "optional group name")

	annotateCmd.AddCommand(annotateGroupCmd)
	annotateCmd.AddCommand(annotateGroupsCmd)
	annotateCmd.AddCommand(annotateUngroupCmd)
}
