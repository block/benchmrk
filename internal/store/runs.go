package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CreateRun inserts a new run and returns its ID.
func (s *Store) CreateRun(ctx context.Context, r *Run) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO runs (experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, log_path, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.ExperimentID, r.ScannerID, r.ProjectID, r.Iteration, r.Status, r.StartedAt, r.CompletedAt, r.DurationMs, r.MemoryPeakBytes, r.SarifPath, r.LogPath, r.ErrorMessage)
	if err != nil {
		return 0, fmt.Errorf("insert run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// GetRun retrieves a run by ID.
func (s *Store) GetRun(ctx context.Context, id int64) (*Run, error) {
	r := &Run{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, log_path, error_message, matcher_version, annotation_hash, created_at
		FROM runs
		WHERE id = ?
	`, id).Scan(&r.ID, &r.ExperimentID, &r.ScannerID, &r.ProjectID, &r.Iteration, &r.Status, &r.StartedAt, &r.CompletedAt, &r.DurationMs, &r.MemoryPeakBytes, &r.SarifPath, &r.LogPath, &r.ErrorMessage, &r.MatcherVersion, &r.AnnotationHash, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query run: %w", err)
	}
	return r, nil
}

// ListRunsByExperiment returns all runs for an experiment. Returns an empty slice (not nil) if none exist.
func (s *Store) ListRunsByExperiment(ctx context.Context, experimentID int64) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, log_path, error_message, matcher_version, annotation_hash, created_at
		FROM runs
		WHERE experiment_id = ?
		ORDER BY scanner_id, project_id, iteration
	`, experimentID)
	if err != nil {
		return nil, fmt.Errorf("query runs by experiment: %w", err)
	}
	defer rows.Close()

	runs := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.ExperimentID, &r.ScannerID, &r.ProjectID, &r.Iteration, &r.Status, &r.StartedAt, &r.CompletedAt, &r.DurationMs, &r.MemoryPeakBytes, &r.SarifPath, &r.LogPath, &r.ErrorMessage, &r.MatcherVersion, &r.AnnotationHash, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runs: %w", err)
	}
	return runs, nil
}

// UpdateRunStatus updates the status and related fields of a run.
func (s *Store) UpdateRunStatus(ctx context.Context, id int64, status RunStatus, startedAt, completedAt sql.NullTime, durationMs, memoryPeakBytes sql.NullInt64, sarifPath, logPath, errorMessage sql.NullString) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE runs
		SET status = ?, started_at = ?, completed_at = ?, duration_ms = ?, memory_peak_bytes = ?, sarif_path = ?, log_path = ?, error_message = ?
		WHERE id = ?
	`, status, startedAt, completedAt, durationMs, memoryPeakBytes, sarifPath, logPath, errorMessage, id)
	if err != nil {
		return fmt.Errorf("update run status: %w", err)
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

// StampRunScorer records which matcher version and annotation set produced
// this run's finding_matches rows. Called by analysis.MatchRun immediately
// before matching — not by the experiment executor — because the scorer
// that matters is the one that wrote the matches, not the one that was
// current when the scanner ran. Re-scoring after clearing finding_matches
// re-stamps.
func (s *Store) StampRunScorer(ctx context.Context, runID int64, matcherVersion, annotationHash string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE runs SET matcher_version = ?, annotation_hash = ? WHERE id = ?
	`, matcherVersion, annotationHash, runID)
	if err != nil {
		return fmt.Errorf("stamp run scorer: %w", err)
	}
	return nil
}

// ListPendingRuns returns all pending or failed runs for an experiment (for resume).
// Returns an empty slice (not nil) if none exist.
func (s *Store) ListPendingRuns(ctx context.Context, experimentID int64) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, log_path, error_message, matcher_version, annotation_hash, created_at
		FROM runs
		WHERE experiment_id = ? AND status IN ('pending', 'failed')
		ORDER BY scanner_id, project_id, iteration
	`, experimentID)
	if err != nil {
		return nil, fmt.Errorf("query pending runs: %w", err)
	}
	defer rows.Close()

	runs := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.ExperimentID, &r.ScannerID, &r.ProjectID, &r.Iteration, &r.Status, &r.StartedAt, &r.CompletedAt, &r.DurationMs, &r.MemoryPeakBytes, &r.SarifPath, &r.LogPath, &r.ErrorMessage, &r.MatcherVersion, &r.AnnotationHash, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runs: %w", err)
	}
	return runs, nil
}

// ListRunsByScannerProject returns all runs for a scanner/project combination.
// Returns an empty slice (not nil) if none exist.
func (s *Store) ListRunsByScannerProject(ctx context.Context, scannerID, projectID int64) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, log_path, error_message, matcher_version, annotation_hash, created_at
		FROM runs
		WHERE scanner_id = ? AND project_id = ?
		ORDER BY created_at DESC
	`, scannerID, projectID)
	if err != nil {
		return nil, fmt.Errorf("query runs by scanner/project: %w", err)
	}
	defer rows.Close()

	runs := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.ExperimentID, &r.ScannerID, &r.ProjectID, &r.Iteration, &r.Status, &r.StartedAt, &r.CompletedAt, &r.DurationMs, &r.MemoryPeakBytes, &r.SarifPath, &r.LogPath, &r.ErrorMessage, &r.MatcherVersion, &r.AnnotationHash, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runs: %w", err)
	}
	return runs, nil
}

// ListRunsByProject returns all runs for a project across all scanners
// and experiments. Used by rescore to enumerate everything that needs
// re-matching when the project's ground truth changes.
func (s *Store) ListRunsByProject(ctx context.Context, projectID int64) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, experiment_id, scanner_id, project_id, iteration, status, started_at, completed_at, duration_ms, memory_peak_bytes, sarif_path, log_path, error_message, matcher_version, annotation_hash, created_at
		FROM runs
		WHERE project_id = ?
		ORDER BY id
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query runs by project: %w", err)
	}
	defer rows.Close()

	runs := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.ExperimentID, &r.ScannerID, &r.ProjectID, &r.Iteration, &r.Status, &r.StartedAt, &r.CompletedAt, &r.DurationMs, &r.MemoryPeakBytes, &r.SarifPath, &r.LogPath, &r.ErrorMessage, &r.MatcherVersion, &r.AnnotationHash, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate runs: %w", err)
	}
	return runs, nil
}

// DeleteRun removes a run by ID. Findings are cascade deleted.
func (s *Store) DeleteRun(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete run: %w", err)
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
