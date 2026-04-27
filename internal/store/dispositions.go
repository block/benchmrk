package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CreateDisposition inserts or replaces a finding disposition and returns its ID.
func (s *Store) CreateDisposition(ctx context.Context, d *FindingDisposition) (int64, error) {
	if !IsValidDisposition(d.Disposition) {
		return 0, fmt.Errorf("invalid disposition %q", d.Disposition)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO finding_dispositions (finding_id, disposition, notes, reviewed_by)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(finding_id) DO UPDATE SET
			disposition = excluded.disposition,
			notes = excluded.notes,
			reviewed_by = excluded.reviewed_by
	`, d.FindingID, d.Disposition, d.Notes, d.ReviewedBy)
	if err != nil {
		return 0, fmt.Errorf("upsert disposition: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// GetDisposition retrieves a disposition by ID.
func (s *Store) GetDisposition(ctx context.Context, id int64) (*FindingDisposition, error) {
	var d FindingDisposition
	err := s.db.QueryRowContext(ctx, `
		SELECT id, finding_id, disposition, notes, reviewed_by, created_at
		FROM finding_dispositions
		WHERE id = ?
	`, id).Scan(&d.ID, &d.FindingID, &d.Disposition, &d.Notes, &d.ReviewedBy, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query disposition: %w", err)
	}
	return &d, nil
}

// GetDispositionByFinding retrieves a disposition by finding ID.
func (s *Store) GetDispositionByFinding(ctx context.Context, findingID int64) (*FindingDisposition, error) {
	var d FindingDisposition
	err := s.db.QueryRowContext(ctx, `
		SELECT id, finding_id, disposition, notes, reviewed_by, created_at
		FROM finding_dispositions
		WHERE finding_id = ?
	`, findingID).Scan(&d.ID, &d.FindingID, &d.Disposition, &d.Notes, &d.ReviewedBy, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query disposition by finding: %w", err)
	}
	return &d, nil
}

// ListDispositionsByRun returns all dispositions for findings in a given run.
// Returns an empty slice (not nil) if none exist.
func (s *Store) ListDispositionsByRun(ctx context.Context, runID int64) ([]FindingDisposition, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT fd.id, fd.finding_id, fd.disposition, fd.notes, fd.reviewed_by, fd.created_at
		FROM finding_dispositions fd
		INNER JOIN findings f ON f.id = fd.finding_id
		WHERE f.run_id = ?
		ORDER BY fd.finding_id
	`, runID)
	if err != nil {
		return nil, fmt.Errorf("query dispositions by run: %w", err)
	}
	defer rows.Close()

	dispositions := []FindingDisposition{}
	for rows.Next() {
		var d FindingDisposition
		if err := rows.Scan(&d.ID, &d.FindingID, &d.Disposition, &d.Notes, &d.ReviewedBy, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan disposition: %w", err)
		}
		dispositions = append(dispositions, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dispositions: %w", err)
	}
	return dispositions, nil
}

// DeleteDisposition removes a disposition by ID.
func (s *Store) DeleteDisposition(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM finding_dispositions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete disposition: %w", err)
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
