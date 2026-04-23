package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// CreateExperiment inserts a new experiment and returns its ID.
func (s *Store) CreateExperiment(ctx context.Context, e *Experiment) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO experiments (name, description, iterations)
		VALUES (?, ?, ?)
	`, e.Name, e.Description, e.Iterations)
	if err != nil {
		return 0, fmt.Errorf("insert experiment: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// GetExperiment retrieves an experiment by ID.
func (s *Store) GetExperiment(ctx context.Context, id int64) (*Experiment, error) {
	e := &Experiment{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, iterations, created_at
		FROM experiments
		WHERE id = ?
	`, id).Scan(&e.ID, &e.Name, &e.Description, &e.Iterations, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query experiment: %w", err)
	}
	return e, nil
}

// GetExperimentByName retrieves an experiment by name.
func (s *Store) GetExperimentByName(ctx context.Context, name string) (*Experiment, error) {
	e := &Experiment{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, iterations, created_at
		FROM experiments
		WHERE name = ?
	`, name).Scan(&e.ID, &e.Name, &e.Description, &e.Iterations, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query experiment by name: %w", err)
	}
	return e, nil
}

// ListExperiments returns all experiments. Returns an empty slice (not nil) if none exist.
func (s *Store) ListExperiments(ctx context.Context) ([]Experiment, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, iterations, created_at
		FROM experiments
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query experiments: %w", err)
	}
	defer rows.Close()

	experiments := []Experiment{}
	for rows.Next() {
		var e Experiment
		if err := rows.Scan(&e.ID, &e.Name, &e.Description, &e.Iterations, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan experiment: %w", err)
		}
		experiments = append(experiments, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate experiments: %w", err)
	}
	return experiments, nil
}

// DeleteExperiment removes an experiment by ID. Cascade deletes experiment_scanners and experiment_projects.
func (s *Store) DeleteExperiment(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM experiments WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete experiment: %w", err)
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

// AddScannerToExperiment links a scanner to an experiment.
func (s *Store) AddScannerToExperiment(ctx context.Context, experimentID, scannerID int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO experiment_scanners (experiment_id, scanner_id)
		VALUES (?, ?)
	`, experimentID, scannerID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil // Already linked, treat as success
		}
		return fmt.Errorf("add scanner to experiment: %w", err)
	}
	return nil
}

// AddProjectToExperiment links a project to an experiment.
func (s *Store) AddProjectToExperiment(ctx context.Context, experimentID, projectID int64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO experiment_projects (experiment_id, project_id)
		VALUES (?, ?)
	`, experimentID, projectID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil // Already linked, treat as success
		}
		return fmt.Errorf("add project to experiment: %w", err)
	}
	return nil
}

// ListExperimentScanners returns all scanners linked to an experiment.
// Returns an empty slice (not nil) if no scanners are linked.
func (s *Store) ListExperimentScanners(ctx context.Context, experimentID int64) ([]Scanner, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.name, s.version, s.docker_image, s.config_json, s.execution_mode, s.executable_path, s.created_at
		FROM scanners s
		INNER JOIN experiment_scanners es ON es.scanner_id = s.id
		WHERE es.experiment_id = ?
		ORDER BY s.name, s.version
	`, experimentID)
	if err != nil {
		return nil, fmt.Errorf("query experiment scanners: %w", err)
	}
	defer rows.Close()

	scanners := []Scanner{}
	for rows.Next() {
		var sc Scanner
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Version, &sc.DockerImage, &sc.ConfigJSON, &sc.ExecutionMode, &sc.ExecutablePath, &sc.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan scanner: %w", err)
		}
		scanners = append(scanners, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scanners: %w", err)
	}
	return scanners, nil
}

// ListExperimentProjects returns all projects linked to an experiment.
// Returns an empty slice (not nil) if no projects are linked.
func (s *Store) ListExperimentProjects(ctx context.Context, experimentID int64) ([]CorpusProject, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.source_url, p.local_path, p.language, p.commit_sha, p.created_at
		FROM corpus_projects p
		INNER JOIN experiment_projects ep ON ep.project_id = p.id
		WHERE ep.experiment_id = ?
		ORDER BY p.name
	`, experimentID)
	if err != nil {
		return nil, fmt.Errorf("query experiment projects: %w", err)
	}
	defer rows.Close()

	projects := []CorpusProject{}
	for rows.Next() {
		var p CorpusProject
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceURL, &p.LocalPath, &p.Language, &p.CommitSHA, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate projects: %w", err)
	}
	return projects, nil
}

// RemoveScannerFromExperiment unlinks a scanner from an experiment.
func (s *Store) RemoveScannerFromExperiment(ctx context.Context, experimentID, scannerID int64) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM experiment_scanners
		WHERE experiment_id = ? AND scanner_id = ?
	`, experimentID, scannerID)
	if err != nil {
		return fmt.Errorf("remove scanner from experiment: %w", err)
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

// RemoveProjectFromExperiment unlinks a project from an experiment.
func (s *Store) RemoveProjectFromExperiment(ctx context.Context, experimentID, projectID int64) error {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM experiment_projects
		WHERE experiment_id = ? AND project_id = ?
	`, experimentID, projectID)
	if err != nil {
		return fmt.Errorf("remove project from experiment: %w", err)
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
