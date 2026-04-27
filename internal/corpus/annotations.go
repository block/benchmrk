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

// ImportAnnotations imports annotations from a JSON file. The accepted
// shape is the vulnerability envelope: {"vulnerabilities": [...]}.
//
// If replace is true, all existing vulnerabilities for the project are
// cleared before importing. Returns the number of evidence rows
// imported.
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

	// Must start with '{' (ignoring leading whitespace) — the only
	// accepted shape is the vulnerability envelope. Reject everything
	// else up front with an actionable message, rather than letting
	// json.Unmarshal emit something cryptic.
	if !startsWithOpenBrace(data) {
		return 0, fmt.Errorf(`annotation file must start with '{' — expected shape is {"vulnerabilities": [...]}`)
	}

	n, err := s.importVulnerabilities(ctx, project.ID, data, doReplace)
	if err != nil {
		return n, err
	}
	s.recordImport(ctx, project.ID, filePath, "vulnerability")
	return n, nil
}

// startsWithOpenBrace returns true if the first non-whitespace byte in
// data is '{'. Used as the format-shape guard for ImportAnnotations.
func startsWithOpenBrace(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return true
		default:
			return false
		}
	}
	return false
}

// ExportAnnotations exports all vulnerabilities for a project as JSON
// in the {"vulnerabilities": [...]} envelope — the same shape
// ImportAnnotations accepts, so export → re-import is lossless. Reads
// straight from the vuln tables (Vulnerability + Evidence + CWEs +
// annotators) rather than the per-evidence Annotation compat surface,
// which would drop CWE sets, annotator lists, criticality, and the
// evidence grouping.
func (s *Service) ExportAnnotations(ctx context.Context, projectName string) ([]byte, error) {
	// Find project by name
	project, err := s.store.GetProjectByName(ctx, projectName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrProjectNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get project: %w", err)
	}

	vulns, err := s.store.ListVulnerabilitiesByProject(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list vulnerabilities: %w", err)
	}
	cwes, err := s.store.ListVulnCWEs(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list vuln cwes: %w", err)
	}
	annotators, err := s.store.ListVulnAnnotatorsByProject(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list vuln annotators: %w", err)
	}
	evidence, err := s.store.ListEvidenceByProject(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}

	// Bucket evidence by vuln — ListEvidenceByProject returns every
	// evidence row across the project in one pass; per-vuln round
	// trips would be N+1.
	evByVuln := make(map[int64][]store.Evidence, len(vulns))
	for _, e := range evidence {
		evByVuln[e.VulnID] = append(evByVuln[e.VulnID], e)
	}

	env := vulnFileEnvelope{
		Vulnerabilities: make([]VulnerabilityJSON, 0, len(vulns)),
	}
	for _, v := range vulns {
		vj := VulnerabilityJSON{
			Name:        v.Name,
			Criticality: v.Criticality,
			Status:      v.Status,
			CWEs:        cwes[v.ID],
			AnnotatedBy: annotators[v.ID],
		}
		if v.Description.Valid {
			vj.Description = v.Description.String
		}

		ev := evByVuln[v.ID]
		vj.Evidence = make([]EvidenceJSON, 0, len(ev))
		for _, e := range ev {
			ej := EvidenceJSON{
				File:     e.FilePath,
				Line:     e.StartLine,
				Role:     e.Role,
				Category: e.Category,
				Severity: e.Severity,
			}
			if e.EndLine.Valid {
				end := int(e.EndLine.Int64)
				ej.End = &end
			}
			vj.Evidence = append(vj.Evidence, ej)
		}

		env.Vulnerabilities = append(env.Vulnerabilities, vj)
	}

	// Marshal with indentation for readability
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}

	return data, nil
}
