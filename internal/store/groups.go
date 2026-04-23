package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Compat shim for annotation groups — migration 010 folded groups into
// the vulnerability model. A "group" is now a vulnerability with more
// than one evidence row. Read methods synthesize from that; write
// methods fail with a pointer to the new API.
//
// The only caller that matters is analysis.annotationHash, which reads
// ListAllGroupMembersByProject to include group structure in the
// scorer hash. That works: the synthesized members are a deterministic
// projection of vuln_evidence, so the hash is stable.

// errGroupsMigrated is returned by group write methods. The message
// explains the migration rather than just failing — a caller hitting
// this is probably someone with an old script who needs to know what
// changed.
var errGroupsMigrated = errors.New(
	"annotation groups were folded into the vulnerability model (migration 010); " +
		"use store.CreateEvidence to add a location to an existing vulnerability, " +
		"or store.BulkCreateVulnerabilities for the new import format")

func (s *Store) CreateAnnotationGroup(ctx context.Context, g *AnnotationGroup) (int64, error) {
	return 0, errGroupsMigrated
}

func (s *Store) AddAnnotationToGroup(ctx context.Context, groupID, annotationID int64, role string) error {
	return errGroupsMigrated
}

func (s *Store) RemoveAnnotationFromGroup(ctx context.Context, groupID, annotationID int64) error {
	return errGroupsMigrated
}

func (s *Store) DeleteAnnotationGroup(ctx context.Context, id int64) error {
	return errGroupsMigrated
}

// GetAnnotationGroup synthesizes a group from a multi-evidence vuln.
// The "group ID" is the vuln ID. Single-evidence vulns return
// ErrNotFound — they're not groups.
func (s *Store) GetAnnotationGroup(ctx context.Context, id int64) (*AnnotationGroup, error) {
	var g AnnotationGroup
	var evidenceCount int
	err := s.db.QueryRowContext(ctx, `
		SELECT v.id, v.project_id, v.name, v.created_at,
		       (SELECT COUNT(*) FROM vuln_evidence WHERE vuln_id = v.id)
		FROM vulnerabilities v WHERE v.id = ?
	`, id).Scan(&g.ID, &g.ProjectID, &g.Name, &g.CreatedAt, &evidenceCount)
	if errors.Is(err, sql.ErrNoRows) || evidenceCount <= 1 {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query group: %w", err)
	}
	return &g, nil
}

// ListAnnotationGroupsByProject returns vulns with >1 evidence row.
func (s *Store) ListAnnotationGroupsByProject(ctx context.Context, projectID int64) ([]AnnotationGroup, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.id, v.project_id, v.name, v.created_at
		FROM vulnerabilities v
		WHERE v.project_id = ?
		  AND (SELECT COUNT(*) FROM vuln_evidence WHERE vuln_id = v.id) > 1
		ORDER BY v.id
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query groups: %w", err)
	}
	defer rows.Close()

	out := []AnnotationGroup{}
	for rows.Next() {
		var g AnnotationGroup
		if err := rows.Scan(&g.ID, &g.ProjectID, &g.Name, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListGroupMembers returns evidence rows for a multi-evidence vuln.
// GroupID == vuln_id, AnnotationID == evidence_id.
func (s *Store) ListGroupMembers(ctx context.Context, groupID int64) ([]AnnotationGroupMember, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT vuln_id, id, role FROM vuln_evidence
		WHERE vuln_id = ? ORDER BY id
	`, groupID)
	if err != nil {
		return nil, fmt.Errorf("query members: %w", err)
	}
	defer rows.Close()

	out := []AnnotationGroupMember{}
	for rows.Next() {
		var m AnnotationGroupMember
		var role string
		if err := rows.Scan(&m.GroupID, &m.AnnotationID, &role); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		// Evidence role vocab is sink|source|helper|related; group role
		// was source|sink|related. Map helper → related.
		if role == "helper" {
			role = "related"
		}
		m.Role = role
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListGroupsByAnnotation returns the "group" (vuln) an evidence row
// belongs to — but only if that vuln has siblings. Solo evidence
// belongs to no group in compat terms.
func (s *Store) ListGroupsByAnnotation(ctx context.Context, annotationID int64) ([]AnnotationGroup, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.id, v.project_id, v.name, v.created_at
		FROM vulnerabilities v
		JOIN vuln_evidence e ON e.vuln_id = v.id
		WHERE e.id = ?
		  AND (SELECT COUNT(*) FROM vuln_evidence WHERE vuln_id = v.id) > 1
	`, annotationID)
	if err != nil {
		return nil, fmt.Errorf("query groups by annotation: %w", err)
	}
	defer rows.Close()

	out := []AnnotationGroup{}
	for rows.Next() {
		var g AnnotationGroup
		if err := rows.Scan(&g.ID, &g.ProjectID, &g.Name, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListAllGroupMembersByProject is what the scorer hash reads.
// Synthesized from multi-evidence vulns: each evidence row becomes a
// "member" of its vuln-as-group.
func (s *Store) ListAllGroupMembersByProject(ctx context.Context, projectID int64) ([]AnnotationGroupMember, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.vuln_id, e.id, e.role
		FROM vuln_evidence e
		JOIN vulnerabilities v ON v.id = e.vuln_id
		WHERE v.project_id = ?
		  AND e.vuln_id IN (
		      SELECT vuln_id FROM vuln_evidence GROUP BY vuln_id HAVING COUNT(*) > 1
		  )
		ORDER BY e.vuln_id, e.id
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query all members: %w", err)
	}
	defer rows.Close()

	out := []AnnotationGroupMember{}
	for rows.Next() {
		var m AnnotationGroupMember
		var role string
		if err := rows.Scan(&m.GroupID, &m.AnnotationID, &role); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		if role == "helper" {
			role = "related"
		}
		m.Role = role
		out = append(out, m)
	}
	return out, rows.Err()
}
