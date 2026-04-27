package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CreateScanner inserts a new scanner and returns its ID.
func (s *Store) CreateScanner(ctx context.Context, sc *Scanner) (int64, error) {
	executionMode := sc.ExecutionMode
	if executionMode == "" {
		executionMode = "docker"
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO scanners (name, version, docker_image, config_json, execution_mode, executable_path)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sc.Name, sc.Version, sc.DockerImage, sc.ConfigJSON, executionMode, sc.ExecutablePath)
	if err != nil {
		return 0, fmt.Errorf("insert scanner: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// GetScanner retrieves a scanner by ID.
func (s *Store) GetScanner(ctx context.Context, id int64) (*Scanner, error) {
	sc := &Scanner{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, version, docker_image, config_json, execution_mode, executable_path, created_at
		FROM scanners
		WHERE id = ?
	`, id).Scan(&sc.ID, &sc.Name, &sc.Version, &sc.DockerImage, &sc.ConfigJSON, &sc.ExecutionMode, &sc.ExecutablePath, &sc.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query scanner: %w", err)
	}
	return sc, nil
}

// GetScannerByNameVersion retrieves a scanner by its unique name+version combination.
func (s *Store) GetScannerByNameVersion(ctx context.Context, name, version string) (*Scanner, error) {
	sc := &Scanner{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, version, docker_image, config_json, execution_mode, executable_path, created_at
		FROM scanners
		WHERE name = ? AND version = ?
	`, name, version).Scan(&sc.ID, &sc.Name, &sc.Version, &sc.DockerImage, &sc.ConfigJSON, &sc.ExecutionMode, &sc.ExecutablePath, &sc.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query scanner by name/version: %w", err)
	}
	return sc, nil
}

// GetScannerByName retrieves the first scanner matching a name (newest version).
func (s *Store) GetScannerByName(ctx context.Context, name string) (*Scanner, error) {
	sc := &Scanner{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, version, docker_image, config_json, execution_mode, executable_path, created_at
		FROM scanners
		WHERE name = ?
		ORDER BY created_at DESC
		LIMIT 1
	`, name).Scan(&sc.ID, &sc.Name, &sc.Version, &sc.DockerImage, &sc.ConfigJSON, &sc.ExecutionMode, &sc.ExecutablePath, &sc.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query scanner by name: %w", err)
	}
	return sc, nil
}

// ListScanners returns all scanners. Returns an empty slice (not nil) if none exist.
func (s *Store) ListScanners(ctx context.Context) ([]Scanner, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, version, docker_image, config_json, execution_mode, executable_path, created_at
		FROM scanners
		ORDER BY name, version
	`)
	if err != nil {
		return nil, fmt.Errorf("query scanners: %w", err)
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

// DeleteScanner removes a scanner by ID.
func (s *Store) DeleteScanner(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM scanners WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete scanner: %w", err)
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
