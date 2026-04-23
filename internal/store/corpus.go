package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNotFound is returned when a requested entity does not exist.
var ErrNotFound = errors.New("not found")

// CreateProject inserts a new corpus project and returns its ID.
func (s *Store) CreateProject(ctx context.Context, p *CorpusProject) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO corpus_projects (name, source_url, local_path, language, commit_sha)
		VALUES (?, ?, ?, ?, ?)
	`, p.Name, p.SourceURL, p.LocalPath, p.Language, p.CommitSHA)
	if err != nil {
		return 0, fmt.Errorf("insert project: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get last insert id: %w", err)
	}
	return id, nil
}

// GetProject retrieves a project by ID.
func (s *Store) GetProject(ctx context.Context, id int64) (*CorpusProject, error) {
	p := &CorpusProject{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, source_url, local_path, language, commit_sha, created_at
		FROM corpus_projects
		WHERE id = ?
	`, id).Scan(&p.ID, &p.Name, &p.SourceURL, &p.LocalPath, &p.Language, &p.CommitSHA, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query project: %w", err)
	}
	return p, nil
}

// GetProjectByName retrieves a project by its unique name.
func (s *Store) GetProjectByName(ctx context.Context, name string) (*CorpusProject, error) {
	p := &CorpusProject{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, source_url, local_path, language, commit_sha, created_at
		FROM corpus_projects
		WHERE name = ?
	`, name).Scan(&p.ID, &p.Name, &p.SourceURL, &p.LocalPath, &p.Language, &p.CommitSHA, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query project by name: %w", err)
	}
	return p, nil
}

// ListProjects returns all projects. Returns an empty slice (not nil) if none exist.
func (s *Store) ListProjects(ctx context.Context) ([]CorpusProject, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, source_url, local_path, language, commit_sha, created_at
		FROM corpus_projects
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("query projects: %w", err)
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

// DeleteProject removes a project by ID. Annotations are cascade deleted.
func (s *Store) DeleteProject(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM corpus_projects WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
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
