package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Compat shim — migration 010 replaced the annotations table with
// vulnerabilities + vuln_evidence + vuln_cwes + vuln_annotators. The
// Annotation Go type stays so the matcher, metrics, and corpus import
// paths that predate the inversion keep working unchanged.
//
// Mapping:
//
//	Annotation.ID       ← vuln_evidence.id       (preserved through migration)
//	         .ProjectID ← vulnerabilities.project_id
//	         .FilePath  ← vuln_evidence.file_path
//	         .StartLine ← vuln_evidence.start_line
//	         .EndLine   ← vuln_evidence.end_line
//	         .CWEID     ← first(vuln_cwes.cwe_id)    — LOSSY: one of N
//	         .Category  ← vuln_evidence.category
//	         .Severity  ← vuln_evidence.severity
//	         .Description ← vulnerabilities.description
//	         .Status    ← vulnerabilities.status
//	         .AnnotatedBy ← first(vuln_annotators)    — LOSSY: one of N
//
// The lossy fields are fine for display. The matcher doesn't use this
// path — it reads evidence + CWE sets natively.
//
// Writes through this shim create single-evidence vulns. That's the
// degenerate case where the new model collapses to the old one, so
// round-trips are clean. Callers that want multi-evidence vulns or
// CWE sets use the native vulns.go interface.

// annotationCompatSelect is the common SELECT for synthesizing
// Annotation rows from the vuln tables. Pulled out so every read
// method uses the identical projection — drift between them would be
// a nightmare to debug.
const annotationCompatSelect = `
	SELECT
		e.id,
		v.project_id,
		e.file_path,
		e.start_line,
		e.end_line,
		(SELECT cwe_id FROM vuln_cwes WHERE vuln_id = v.id ORDER BY cwe_id LIMIT 1),
		e.category,
		e.severity,
		v.description,
		v.status,
		(SELECT annotated_by FROM vuln_annotators WHERE vuln_id = v.id ORDER BY created_at LIMIT 1),
		e.created_at,
		v.updated_at
	FROM vuln_evidence e
	JOIN vulnerabilities v ON v.id = e.vuln_id`

func scanAnnotationCompat(scan func(...any) error) (Annotation, error) {
	var a Annotation
	err := scan(&a.ID, &a.ProjectID, &a.FilePath, &a.StartLine, &a.EndLine,
		&a.CWEID, &a.Category, &a.Severity, &a.Description, &a.Status,
		&a.AnnotatedBy, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

// CreateAnnotation creates a single-evidence vulnerability and returns
// the evidence row's ID — which callers treat as "the annotation ID"
// exactly as before. The vulnerability name is synthesized from
// category + location, matching what migration 010 did for solo
// annotations.
func (s *Store) CreateAnnotation(ctx context.Context, a *Annotation) (int64, error) {
	if !IsValidAnnotationStatus(a.Status) {
		return 0, fmt.Errorf("invalid annotation status %q", a.Status)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	eid, err := createAnnotationCompat(ctx, tx, a)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return eid, nil
}

// createAnnotationCompat does the four inserts for one compat
// annotation. Extracted so BulkCreateAnnotations can call it inside
// its own transaction without nesting.
func createAnnotationCompat(ctx context.Context, tx *sql.Tx, a *Annotation) (int64, error) {
	name := fmt.Sprintf("%s @ %s:%d", a.Category, a.FilePath, a.StartLine)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO vulnerabilities (project_id, name, description, criticality, status)
		VALUES (?, ?, ?, 'should', ?)
	`, a.ProjectID, name, a.Description, a.Status)
	if err != nil {
		return 0, fmt.Errorf("insert vuln: %w", err)
	}
	vid, _ := res.LastInsertId()

	res, err = tx.ExecContext(ctx, `
		INSERT INTO vuln_evidence (vuln_id, file_path, start_line, end_line, role, category, severity)
		VALUES (?, ?, ?, ?, 'sink', ?, ?)
	`, vid, a.FilePath, a.StartLine, a.EndLine, a.Category, a.Severity)
	if err != nil {
		return 0, fmt.Errorf("insert evidence: %w", err)
	}
	eid, _ := res.LastInsertId()

	if a.CWEID.Valid && a.CWEID.String != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_cwes (vuln_id, cwe_id) VALUES (?, ?)
		`, vid, a.CWEID.String); err != nil {
			return 0, fmt.Errorf("insert cwe: %w", err)
		}
	}

	if a.AnnotatedBy.Valid && a.AnnotatedBy.String != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_annotators (vuln_id, annotated_by) VALUES (?, ?)
		`, vid, a.AnnotatedBy.String); err != nil {
			return 0, fmt.Errorf("insert annotator: %w", err)
		}
	}

	return eid, nil
}

func (s *Store) GetAnnotation(ctx context.Context, id int64) (*Annotation, error) {
	a, err := scanAnnotationCompat(s.db.QueryRowContext(ctx,
		annotationCompatSelect+` WHERE e.id = ?`, id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query annotation: %w", err)
	}
	return &a, nil
}

func (s *Store) ListAnnotationsByProject(ctx context.Context, projectID int64) ([]Annotation, error) {
	rows, err := s.db.QueryContext(ctx,
		annotationCompatSelect+` WHERE v.project_id = ? ORDER BY e.file_path, e.start_line`,
		projectID)
	if err != nil {
		return nil, fmt.Errorf("query annotations: %w", err)
	}
	defer rows.Close()

	out := []Annotation{}
	for rows.Next() {
		a, err := scanAnnotationCompat(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan annotation: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAnnotation writes through to both the evidence row (location,
// category, severity) and its parent vuln (status, description). The
// CWE and annotator fields replace the vuln's FIRST entry — callers
// going through this shim are thinking in single-CWE terms anyway.
//
// If the evidence belongs to a multi-evidence vuln, the status and
// description changes affect the whole vuln. That's arguably
// surprising, but it's what "update this annotation's status" meant
// under the old group semantics too (groups never had their own
// status; they inherited from members).
func (s *Store) UpdateAnnotation(ctx context.Context, a *Annotation) error {
	if !IsValidAnnotationStatus(a.Status) {
		return fmt.Errorf("invalid annotation status %q", a.Status)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var vid int64
	if err := tx.QueryRowContext(ctx,
		`SELECT vuln_id FROM vuln_evidence WHERE id = ?`, a.ID,
	).Scan(&vid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup vuln: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE vuln_evidence
		SET file_path = ?, start_line = ?, end_line = ?, category = ?, severity = ?
		WHERE id = ?
	`, a.FilePath, a.StartLine, a.EndLine, a.Category, a.Severity, a.ID); err != nil {
		return fmt.Errorf("update evidence: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE vulnerabilities
		SET description = ?, status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, a.Description, a.Status, vid); err != nil {
		return fmt.Errorf("update vuln: %w", err)
	}

	// CWE: replace the set with exactly this one. Compat callers think
	// in single-CWE terms. Native callers that set multiple CWEs should
	// not also update through this shim.
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_cwes WHERE vuln_id = ?`, vid); err != nil {
		return fmt.Errorf("clear cwes: %w", err)
	}
	if a.CWEID.Valid && a.CWEID.String != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_cwes (vuln_id, cwe_id) VALUES (?, ?)
		`, vid, a.CWEID.String); err != nil {
			return fmt.Errorf("set cwe: %w", err)
		}
	}

	// Annotator: same replace semantics.
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_annotators WHERE vuln_id = ?`, vid); err != nil {
		return fmt.Errorf("clear annotators: %w", err)
	}
	if a.AnnotatedBy.Valid && a.AnnotatedBy.String != "" {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vuln_annotators (vuln_id, annotated_by) VALUES (?, ?)
		`, vid, a.AnnotatedBy.String); err != nil {
			return fmt.Errorf("set annotator: %w", err)
		}
	}

	return tx.Commit()
}

// DeleteAnnotation removes one evidence row. If it was the vuln's only
// evidence, the vuln goes too — a vulnerability with no observable
// location is meaningless. If other evidence remains, the vuln stays
// and only this location is removed.
func (s *Store) DeleteAnnotation(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var vid int64
	if err := tx.QueryRowContext(ctx,
		`SELECT vuln_id FROM vuln_evidence WHERE id = ?`, id,
	).Scan(&vid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup vuln: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_evidence WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete evidence: %w", err)
	}

	var remaining int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM vuln_evidence WHERE vuln_id = ?`, vid,
	).Scan(&remaining); err != nil {
		return fmt.Errorf("count remaining evidence: %w", err)
	}
	if remaining == 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE id = ?`, vid); err != nil {
			return fmt.Errorf("delete orphan vuln: %w", err)
		}
	}

	return tx.Commit()
}

// DeleteAnnotationsByProject removes everything. Under the hood this
// is DeleteVulnerabilitiesByProject — the cascade takes evidence,
// cwes, and annotators with it. Returns the evidence-row count (not
// the vuln count) because callers expect "number of annotations
// deleted."
func (s *Store) DeleteAnnotationsByProject(ctx context.Context, projectID int64) (int64, error) {
	// Count evidence first; the DELETE cascade won't tell us.
	var n int64
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM vuln_evidence e
		JOIN vulnerabilities v ON v.id = e.vuln_id
		WHERE v.project_id = ?
	`, projectID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count evidence: %w", err)
	}

	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM vulnerabilities WHERE project_id = ?`, projectID,
	); err != nil {
		return 0, fmt.Errorf("delete vulnerabilities: %w", err)
	}
	return n, nil
}

// BulkCreateAnnotations inserts N single-evidence vulns in one
// transaction via the Annotation compat type. Retained alongside the
// Annotation shim for one-row-at-a-time callers; the file-import path
// uses BulkCreateVulnerabilities directly.
func (s *Store) BulkCreateAnnotations(ctx context.Context, annotations []Annotation) error {
	if len(annotations) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	for i := range annotations {
		a := &annotations[i]
		if !IsValidAnnotationStatus(a.Status) {
			return fmt.Errorf("annotation %d: invalid status %q", i, a.Status)
		}
		if _, err := createAnnotationCompat(ctx, tx, a); err != nil {
			return fmt.Errorf("annotation %d: %w", i, err)
		}
	}

	return tx.Commit()
}
