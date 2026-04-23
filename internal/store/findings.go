package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CreateFinding inserts a new finding and returns its ID.
func (s *Store) CreateFinding(ctx context.Context, f *Finding) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO findings (run_id, rule_id, file_path, start_line, end_line, cwe_id, severity, message, snippet, fingerprint)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.RunID, f.RuleID, f.FilePath, f.StartLine, f.EndLine, f.CWEID, f.Severity, f.Message, f.Snippet, f.Fingerprint)
	if err != nil {
		return 0, fmt.Errorf("insert finding: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// BulkCreateFindings inserts multiple findings in a single transaction.
// If any insert fails, the entire batch is rolled back.
func (s *Store) BulkCreateFindings(ctx context.Context, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings (run_id, rule_id, file_path, start_line, end_line, cwe_id, severity, message, snippet, fingerprint)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for i, f := range findings {
		_, err := stmt.ExecContext(ctx, f.RunID, f.RuleID, f.FilePath, f.StartLine, f.EndLine, f.CWEID, f.Severity, f.Message, f.Snippet, f.Fingerprint)
		if err != nil {
			return fmt.Errorf("insert finding %d: %w", i, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// GetFinding returns a single finding by ID.
func (s *Store) GetFinding(ctx context.Context, id int64) (*Finding, error) {
	var f Finding
	err := s.db.QueryRowContext(ctx, `
		SELECT id, run_id, rule_id, file_path, start_line, end_line, cwe_id, severity, message, snippet, fingerprint, created_at
		FROM findings
		WHERE id = ?
	`, id).Scan(&f.ID, &f.RunID, &f.RuleID, &f.FilePath, &f.StartLine, &f.EndLine, &f.CWEID, &f.Severity, &f.Message, &f.Snippet, &f.Fingerprint, &f.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query finding: %w", err)
	}
	return &f, nil
}

// ListFindingsByRun returns all findings for a run. Returns an empty slice (not nil) if none exist.
func (s *Store) ListFindingsByRun(ctx context.Context, runID int64) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, run_id, rule_id, file_path, start_line, end_line, cwe_id, severity, message, snippet, fingerprint, created_at
		FROM findings
		WHERE run_id = ?
		ORDER BY file_path, start_line
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query findings by run: %w", err)
	}
	defer rows.Close()

	findings := []Finding{}
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.RunID, &f.RuleID, &f.FilePath, &f.StartLine, &f.EndLine, &f.CWEID, &f.Severity, &f.Message, &f.Snippet, &f.Fingerprint, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}

// ClearFindingMatchesForRun deletes every finding_matches row produced
// by a run's findings. This is derived state — the findings themselves
// are untouched — so the next MatchRun call will recompute from
// scratch and re-stamp the run's matcher_version and annotation_hash.
// Returns the number of rows deleted.
func (s *Store) ClearFindingMatchesForRun(ctx context.Context, runID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM finding_matches
		WHERE finding_id IN (SELECT id FROM findings WHERE run_id = ?)
	`, runID)
	if err != nil {
		return 0, fmt.Errorf("clear finding matches: %w", err)
	}
	return res.RowsAffected()
}

// CreateFindingMatch inserts a new finding match and returns its ID.
// The Go field FindingMatch.AnnotationID lands in the evidence_id
// column — migration 010 renamed it, evidence IDs inherit the old
// annotation ID space, so the value round-trips unchanged.
func (s *Store) CreateFindingMatch(ctx context.Context, m *FindingMatch) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_matches (finding_id, evidence_id, match_type, confidence)
		VALUES (?, ?, ?, ?)
	`, m.FindingID, m.AnnotationID, m.MatchType, m.Confidence)
	if err != nil {
		return 0, fmt.Errorf("insert finding match: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// ListFindingMatchesByRun returns all finding matches for a run.
// Returns an empty slice (not nil) if none exist.
func (s *Store) ListFindingMatchesByRun(ctx context.Context, runID int64) ([]FindingMatch, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT fm.id, fm.finding_id, fm.evidence_id, fm.match_type, fm.confidence, fm.created_at
		FROM finding_matches fm
		INNER JOIN findings f ON f.id = fm.finding_id
		WHERE f.run_id = ?
		ORDER BY fm.finding_id
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query finding matches by run: %w", err)
	}
	defer rows.Close()

	matches := []FindingMatch{}
	for rows.Next() {
		var m FindingMatch
		if err := rows.Scan(&m.ID, &m.FindingID, &m.AnnotationID, &m.MatchType, &m.Confidence, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan finding match: %w", err)
		}
		matches = append(matches, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding matches: %w", err)
	}
	return matches, nil
}

// ListUnmatchedFindings returns findings that have no match entry (false positives).
// Returns an empty slice (not nil) if none exist.
func (s *Store) ListUnmatchedFindings(ctx context.Context, runID int64) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.id, f.run_id, f.rule_id, f.file_path, f.start_line, f.end_line, f.cwe_id, f.severity, f.message, f.snippet, f.fingerprint, f.created_at
		FROM findings f
		LEFT JOIN finding_matches fm ON fm.finding_id = f.id
		WHERE f.run_id = ? AND fm.id IS NULL
		ORDER BY f.file_path, f.start_line
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query unmatched findings: %w", err)
	}
	defer rows.Close()

	findings := []Finding{}
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.RunID, &f.RuleID, &f.FilePath, &f.StartLine, &f.EndLine, &f.CWEID, &f.Severity, &f.Message, &f.Snippet, &f.Fingerprint, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}

// ListUnmatchedAnnotations returns evidence rows that have no match for
// a given run+project. Pre-010 this was per-annotation; now it's
// per-evidence, which is the same thing via the compat shim. Callers
// still computing metrics from this (reports, detail views) get the old
// per-location counting. The headline compare flow uses
// ListUnsatisfiedVulns instead.
func (s *Store) ListUnmatchedAnnotations(ctx context.Context, runID, projectID int64) ([]Annotation, error) {
	rows, err := s.db.QueryContext(ctx, annotationCompatSelect+`
		WHERE v.project_id = ?
		  AND e.id NOT IN (
		    SELECT fm.evidence_id
		    FROM finding_matches fm
		    INNER JOIN findings f ON f.id = fm.finding_id
		    WHERE f.run_id = ?
		  )
		ORDER BY e.file_path, e.start_line
	`, projectID, runID)
	if err != nil {
		return nil, fmt.Errorf("query unmatched annotations: %w", err)
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

// ListSatisfiedVulns returns vulnerabilities where at least one evidence
// row was matched by a finding in this run. These are the TPs (valid)
// or matched-FPs (invalid) under vulnerability-level accounting.
func (s *Store) ListSatisfiedVulns(ctx context.Context, runID, projectID int64) ([]Vulnerability, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT v.id, v.project_id, v.name, v.description, v.criticality, v.status, v.created_at, v.updated_at
		FROM vulnerabilities v
		JOIN vuln_evidence e ON e.vuln_id = v.id
		JOIN finding_matches fm ON fm.evidence_id = e.id
		JOIN findings f ON f.id = fm.finding_id
		WHERE v.project_id = ? AND f.run_id = ?
		ORDER BY v.id
	`, projectID, runID)
	if err != nil {
		return nil, fmt.Errorf("query satisfied vulns: %w", err)
	}
	defer rows.Close()

	out := []Vulnerability{}
	for rows.Next() {
		var v Vulnerability
		if err := rows.Scan(&v.ID, &v.ProjectID, &v.Name, &v.Description, &v.Criticality, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan vuln: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ListUnsatisfiedVulns returns vulnerabilities where NO evidence row was
// matched. Valid ones are FNs; invalid ones are TNs. This plus
// ListSatisfiedVulns plus ListUnmatchedFindings is everything
// ComputeVulnMetrics needs.
func (s *Store) ListUnsatisfiedVulns(ctx context.Context, runID, projectID int64) ([]Vulnerability, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.id, v.project_id, v.name, v.description, v.criticality, v.status, v.created_at, v.updated_at
		FROM vulnerabilities v
		WHERE v.project_id = ?
		  AND NOT EXISTS (
		    SELECT 1
		    FROM vuln_evidence e
		    JOIN finding_matches fm ON fm.evidence_id = e.id
		    JOIN findings f ON f.id = fm.finding_id
		    WHERE e.vuln_id = v.id AND f.run_id = ?
		  )
		ORDER BY v.id
	`, projectID, runID)
	if err != nil {
		return nil, fmt.Errorf("query unsatisfied vulns: %w", err)
	}
	defer rows.Close()

	out := []Vulnerability{}
	for rows.Next() {
		var v Vulnerability
		if err := rows.Scan(&v.ID, &v.ProjectID, &v.Name, &v.Description, &v.Criticality, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan vuln: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteFinding removes a finding by ID. Finding matches are cascade deleted.
func (s *Store) DeleteFinding(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete finding: %w", err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
