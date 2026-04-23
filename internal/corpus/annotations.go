package corpus

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/block/benchmrk/internal/store"
)

// Annotation errors
var (
	ErrInvalidSeverity = errors.New("invalid severity: must be one of critical, high, medium, low, info")
)

// validSeverities lists the allowed severity values.
var validSeverities = []string{"critical", "high", "medium", "low", "info"}

// isValidSeverity checks if the provided severity is valid.
func isValidSeverity(severity string) bool {
	for _, s := range validSeverities {
		if s == severity {
			return true
		}
	}
	return false
}

// AnnotationJSON represents the JSON format for import/export.
type AnnotationJSON struct {
	FilePath    string `json:"file_path"`
	StartLine   int    `json:"start_line"`
	EndLine     *int   `json:"end_line,omitempty"`
	CWEID       string `json:"cwe_id,omitempty"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	Group       string `json:"group,omitempty"`
}

// AddAnnotation adds a new annotation to a project.
func (s *Service) AddAnnotation(ctx context.Context, projectName, filePath string, startLine int, endLine *int, cweID, category, severity, description, status string) (*store.Annotation, error) {
	// Validate severity
	if !isValidSeverity(severity) {
		return nil, ErrInvalidSeverity
	}

	// Validate and default status
	if status == "" {
		status = "valid"
	}
	typedStatus := store.AnnotationStatus(status)
	if !store.IsValidAnnotationStatus(typedStatus) {
		return nil, fmt.Errorf("invalid status %q: must be one of valid, invalid, disputed", status)
	}

	// Find project by name
	project, err := s.store.GetProjectByName(ctx, projectName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	// Build annotation
	a := &store.Annotation{
		ProjectID: project.ID,
		FilePath:  filePath,
		StartLine: startLine,
		Category:  category,
		Severity:  severity,
		Status:    typedStatus,
	}

	if endLine != nil {
		a.EndLine = sql.NullInt64{Int64: int64(*endLine), Valid: true}
	}

	if cweID != "" {
		a.CWEID = sql.NullString{String: cweID, Valid: true}
	}

	if description != "" {
		a.Description = sql.NullString{String: description, Valid: true}
	}

	// Create in store
	id, err := s.store.CreateAnnotation(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("create annotation: %w", err)
	}

	// Fetch and return the created annotation
	return s.store.GetAnnotation(ctx, id)
}

// UpdateAnnotation updates an existing annotation. Only non-zero fields are applied.
func (s *Service) UpdateAnnotation(ctx context.Context, id int64, filePath string, startLine int, endLine *int, cweID, category, severity, description, status string) (*store.Annotation, error) {
	// Fetch existing
	existing, err := s.store.GetAnnotation(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("annotation %d not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("get annotation: %w", err)
	}

	// Apply non-zero updates
	if filePath != "" {
		existing.FilePath = filePath
	}
	if startLine > 0 {
		existing.StartLine = startLine
	}
	if endLine != nil {
		existing.EndLine = sql.NullInt64{Int64: int64(*endLine), Valid: true}
	}
	if cweID != "" {
		existing.CWEID = sql.NullString{String: cweID, Valid: true}
	}
	if category != "" {
		existing.Category = category
	}
	if severity != "" {
		if !isValidSeverity(severity) {
			return nil, ErrInvalidSeverity
		}
		existing.Severity = severity
	}
	if description != "" {
		existing.Description = sql.NullString{String: description, Valid: true}
	}
	if status != "" {
		typedStatus := store.AnnotationStatus(status)
		if !store.IsValidAnnotationStatus(typedStatus) {
			return nil, fmt.Errorf("invalid status %q: must be one of valid, invalid, disputed", status)
		}
		existing.Status = typedStatus
	}

	if err := s.store.UpdateAnnotation(ctx, existing); err != nil {
		return nil, fmt.Errorf("update annotation: %w", err)
	}

	return s.store.GetAnnotation(ctx, id)
}

// DeleteAnnotation deletes an annotation by ID.
func (s *Service) DeleteAnnotation(ctx context.Context, id int64) error {
	if err := s.store.DeleteAnnotation(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("annotation %d not found", id)
		}
		return fmt.Errorf("delete annotation: %w", err)
	}
	return nil
}

// ListAnnotations returns all annotations for a project.
func (s *Service) ListAnnotations(ctx context.Context, projectName string) ([]store.Annotation, error) {
	// Find project by name
	project, err := s.store.GetProjectByName(ctx, projectName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	return s.store.ListAnnotationsByProject(ctx, project.ID)
}

// ImportAnnotations imports annotations from a JSON file.
// If replace is true, all existing annotations for the project are deleted before importing.
// Returns the number of annotations imported.
func (s *Service) ImportAnnotations(ctx context.Context, projectName, filePath string, replace ...bool) (int, error) {
	doReplace := len(replace) > 0 && replace[0]
	// Find project by name
	project, err := s.store.GetProjectByName(ctx, projectName)
	if errors.Is(err, store.ErrNotFound) {
		return 0, ErrProjectNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get project: %w", err)
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("read file: %w", err)
	}

	// Format detection: the new vulnerability format is an object
	// ({"vulnerabilities": [...]}); the legacy format is a bare array.
	// Peek at the first non-whitespace byte. This is cheaper and more
	// robust than trial-unmarshal — an object that ISN'T the vuln
	// envelope should fail with a clear error, not silently fall
	// through to the array path.
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b == '{' {
			n, err := s.importVulnerabilities(ctx, project.ID, data, doReplace)
			if err == nil {
				s.recordImport(ctx, project.ID, filePath, "vulnerability")
			}
			return n, err
		}
		break // '[' or garbage — let the array unmarshal handle it
	}

	// Parse JSON
	var jsonAnnotations []AnnotationJSON
	if err := json.Unmarshal(data, &jsonAnnotations); err != nil {
		return 0, fmt.Errorf("parse JSON: %w", err)
	}

	// Handle empty array
	if len(jsonAnnotations) == 0 {
		return 0, nil
	}

	// Validate and convert to store.Annotation
	annotations := make([]store.Annotation, 0, len(jsonAnnotations))
	for i, ja := range jsonAnnotations {
		// Validate required fields
		if ja.FilePath == "" {
			return 0, fmt.Errorf("annotation %d: file_path is required", i+1)
		}
		if ja.StartLine <= 0 {
			return 0, fmt.Errorf("annotation %d (%s): start_line must be positive", i+1, ja.FilePath)
		}
		if ja.Category == "" {
			return 0, fmt.Errorf("annotation %d (%s:%d): category is required", i+1, ja.FilePath, ja.StartLine)
		}
		if !isValidSeverity(ja.Severity) {
			return 0, fmt.Errorf("annotation %d (%s:%d): invalid severity %q", i+1, ja.FilePath, ja.StartLine, ja.Severity)
		}

		statusStr := ja.Status
		if statusStr == "" {
			statusStr = "valid"
		}
		typedStatus := store.AnnotationStatus(statusStr)
		if !store.IsValidAnnotationStatus(typedStatus) {
			return 0, fmt.Errorf("annotation %d (%s:%d): invalid status %q", i+1, ja.FilePath, ja.StartLine, statusStr)
		}

		a := store.Annotation{
			ProjectID: project.ID,
			FilePath:  ja.FilePath,
			StartLine: ja.StartLine,
			Category:  ja.Category,
			Severity:  ja.Severity,
			Status:    typedStatus,
		}

		if ja.EndLine != nil {
			a.EndLine = sql.NullInt64{Int64: int64(*ja.EndLine), Valid: true}
		}

		if ja.CWEID != "" {
			a.CWEID = sql.NullString{String: ja.CWEID, Valid: true}
		}

		if ja.Description != "" {
			a.Description = sql.NullString{String: ja.Description, Valid: true}
		}

		annotations = append(annotations, a)
	}

	// Delete existing annotations if replacing
	if doReplace {
		if _, err := s.store.DeleteAnnotationsByProject(ctx, project.ID); err != nil {
			return 0, fmt.Errorf("delete existing annotations: %w", err)
		}
	}

	// Bulk insert
	if err := s.store.BulkCreateAnnotations(ctx, annotations); err != nil {
		return 0, fmt.Errorf("bulk insert: %w", err)
	}

	// Legacy group field: migration 010 folded groups into the vuln
	// model and the group-write methods now error. The "group" field on
	// AnnotationJSON is thus dead for legacy imports. Emit a one-line
	// warning and move on — each annotation still becomes a solo vuln,
	// just without the cross-linking.
	//
	// The right fix is to convert the file to the new format (one
	// vulnerability per group, evidence[] for the members). That's a
	// human task — we can't guess which annotation's description/CWE
	// should become the vuln's.
	for _, ja := range jsonAnnotations {
		if ja.Group != "" {
			fmt.Fprintf(os.Stderr,
				"warning: annotation file uses legacy 'group' field; "+
					"groups are ignored under the vulnerability model. "+
					"Convert to the new format ({\"vulnerabilities\": [...]}) "+
					"to express multi-location vulnerabilities.\n")
			break // one warning, not one per annotation
		}
	}

	s.recordImport(ctx, project.ID, filePath, "legacy")
	return len(annotations), nil
}

// ExportAnnotations exports all annotations for a project as JSON.
func (s *Service) ExportAnnotations(ctx context.Context, projectName string) ([]byte, error) {
	// Find project by name
	project, err := s.store.GetProjectByName(ctx, projectName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	// Get annotations
	annotations, err := s.store.ListAnnotationsByProject(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list annotations: %w", err)
	}

	// Load group memberships
	allGroups, err := s.store.ListAnnotationGroupsByProject(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}

	// Build annotation → group name map
	annotationGroupName := make(map[int64]string)
	for _, g := range allGroups {
		members, err := s.store.ListGroupMembers(ctx, g.ID)
		if err != nil {
			continue
		}
		name := fmt.Sprintf("group-%d", g.ID)
		if g.Name.Valid && g.Name.String != "" {
			name = g.Name.String
		}
		for _, m := range members {
			annotationGroupName[m.AnnotationID] = name
		}
	}

	// Convert to JSON format
	jsonAnnotations := make([]AnnotationJSON, 0, len(annotations))
	for _, a := range annotations {
		ja := AnnotationJSON{
			FilePath:  a.FilePath,
			StartLine: a.StartLine,
			Category:  a.Category,
			Severity:  a.Severity,
			Status:    string(a.Status),
		}

		if a.EndLine.Valid {
			endLine := int(a.EndLine.Int64)
			ja.EndLine = &endLine
		}

		if a.CWEID.Valid {
			ja.CWEID = a.CWEID.String
		}

		if a.Description.Valid {
			ja.Description = a.Description.String
		}

		if gName, ok := annotationGroupName[a.ID]; ok {
			ja.Group = gName
		}

		jsonAnnotations = append(jsonAnnotations, ja)
	}

	// Marshal with indentation for readability
	data, err := json.MarshalIndent(jsonAnnotations, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}

	return data, nil
}
