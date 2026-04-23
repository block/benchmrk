package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Vulnerability is the unit of ground truth. One vulnerability may be
// evidenced at many locations (vuln_evidence rows) and may be correctly
// described by many CWEs (vuln_cwes rows). A scanner finding matches the
// vulnerability if it matches any evidence location with any acceptable
// CWE; the vulnerability is then satisfied and scores one TP regardless
// of how many evidence locations were hit.
type Vulnerability struct {
	ID          int64
	ProjectID   int64
	Name        string
	Description sql.NullString
	// Criticality tiers findings for separate recall reporting. A tool
	// that misses a 'must' is worse than one that misses a 'may' at the
	// same overall recall.
	Criticality string // must | should | may
	Status      string // valid | invalid | disputed
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Evidence is one location where a vulnerability manifests. The matcher
// works at this granularity — findings match evidence rows, not vulns —
// and metrics rolls evidence matches up to vulnerability satisfaction.
//
// IDs inherit from the old annotations table (migration 010 preserved
// them) so the compat shim's GetAnnotation(id) is a direct lookup.
type Evidence struct {
	ID        int64
	VulnID    int64
	FilePath  string
	StartLine int
	EndLine   sql.NullInt64
	Role      string // sink | source | helper | related — informational
	Category  string
	Severity  string
	CreatedAt time.Time
}

// AnnotationSet records one import of an annotation file. The hash
// joins to runs.annotation_hash so you can recover "which file
// produced the ground truth this run was scored against."
type AnnotationSet struct {
	ID         int64
	ProjectID  int64
	Hash       string
	SourcePath sql.NullString
	GitSHA     sql.NullString
	VulnCount  int
	Format     string // legacy | vulnerability
	ImportedAt time.Time
}

func (s *Store) RecordAnnotationSet(ctx context.Context, set *AnnotationSet) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO annotation_sets (project_id, hash, source_path, git_sha, vuln_count, format)
		VALUES (?, ?, ?, ?, ?, ?)
	`, set.ProjectID, set.Hash, set.SourcePath, set.GitSHA, set.VulnCount, set.Format)
	if err != nil {
		return 0, fmt.Errorf("record annotation set: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) GetAnnotationSetByHash(ctx context.Context, hash string) (*AnnotationSet, error) {
	a := &AnnotationSet{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, hash, source_path, git_sha, vuln_count, format, imported_at
		FROM annotation_sets WHERE hash = ? ORDER BY imported_at DESC LIMIT 1
	`, hash).Scan(&a.ID, &a.ProjectID, &a.Hash, &a.SourcePath, &a.GitSHA, &a.VulnCount, &a.Format, &a.ImportedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query annotation set: %w", err)
	}
	return a, nil
}

// AnnotationHash computes a stable digest of the project's ground
// truth. Two runs with different hashes were graded against different
// annotation sets and their metrics are not comparable.
//
// Covers every field the matcher and ComputeVulnMetrics read:
// vulnerability name/status/criticality, evidence location/category/
// severity, CWE set. Excludes description, annotators, timestamps —
// edits that don't affect scoring shouldn't churn the hash.
//
// Stable across insert order: everything is sorted before hashing,
// and IDs are resolved to positions so two DBs with the same content
// inserted differently hash the same.
func (s *Store) AnnotationHash(ctx context.Context, projectID int64) (string, error) {
	vulns, err := s.ListVulnerabilitiesByProject(ctx, projectID)
	if err != nil {
		return "", err
	}
	evidence, err := s.ListEvidenceByProject(ctx, projectID)
	if err != nil {
		return "", err
	}
	cwes, err := s.ListVulnCWEs(ctx, projectID)
	if err != nil {
		return "", err
	}

	sort.Slice(vulns, func(i, j int) bool { return vulns[i].Name < vulns[j].Name })
	// Evidence is already ORDER BY file_path, start_line from the query.
	// CWE slices are already sorted per-vuln by the query.

	// Resolve vuln IDs to positions so the hash is ID-independent.
	posOf := make(map[int64]int, len(vulns))
	for i, v := range vulns {
		posOf[v.ID] = i
	}

	h := sha256.New()
	for _, v := range vulns {
		fmt.Fprintf(h, "v|%s|%s|%s\n", v.Name, v.Status, v.Criticality)
		for _, c := range cwes[v.ID] {
			fmt.Fprintf(h, "c|%d|%s\n", posOf[v.ID], c)
		}
	}
	for _, e := range evidence {
		end := int64(e.StartLine)
		if e.EndLine.Valid {
			end = e.EndLine.Int64
		}
		fmt.Fprintf(h, "e|%d|%s|%d|%d|%s|%s\n",
			posOf[e.VulnID], e.FilePath, e.StartLine, end, e.Category, e.Severity)
	}

	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

func (s *Store) ListAnnotationSetsByProject(ctx context.Context, projectID int64) ([]AnnotationSet, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, hash, source_path, git_sha, vuln_count, format, imported_at
		FROM annotation_sets WHERE project_id = ? ORDER BY imported_at DESC
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query annotation sets: %w", err)
	}
	defer rows.Close()

	out := []AnnotationSet{}
	for rows.Next() {
		var a AnnotationSet
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Hash, &a.SourcePath, &a.GitSHA, &a.VulnCount, &a.Format, &a.ImportedAt); err != nil {
			return nil, fmt.Errorf("scan annotation set: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// VulnWithDetail bundles a vulnerability with its evidence locations,
// acceptable CWEs, and annotator list — everything needed to score it
// without further round trips. This is what the matcher and the importer
// want; the flat types above are for CRUD.
type VulnWithDetail struct {
	Vulnerability
	Evidence   []Evidence
	CWEs       []string
	Annotators []string
}

// ── Vulnerability CRUD ──────────────────────────────────────────────

func (s *Store) CreateVulnerability(ctx context.Context, v *Vulnerability) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO vulnerabilities (project_id, name, description, criticality, status)
		VALUES (?, ?, ?, ?, ?)
	`, v.ProjectID, v.Name, v.Description, v.Criticality, v.Status)
	if err != nil {
		return 0, fmt.Errorf("insert vulnerability: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) GetVulnerability(ctx context.Context, id int64) (*Vulnerability, error) {
	v := &Vulnerability{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, name, description, criticality, status, created_at, updated_at
		FROM vulnerabilities WHERE id = ?
	`, id).Scan(&v.ID, &v.ProjectID, &v.Name, &v.Description, &v.Criticality, &v.Status, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query vulnerability: %w", err)
	}
	return v, nil
}

// GetVulnerabilityByName looks up a vulnerability by its name within a
// project. Names are unique per project by convention, not constraint —
// if duplicates exist, the oldest wins. Used by triage --attach-to.
func (s *Store) GetVulnerabilityByName(ctx context.Context, projectID int64, name string) (*Vulnerability, error) {
	v := &Vulnerability{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, name, description, criticality, status, created_at, updated_at
		FROM vulnerabilities WHERE project_id = ? AND name = ? ORDER BY id LIMIT 1
	`, projectID, name).Scan(&v.ID, &v.ProjectID, &v.Name, &v.Description, &v.Criticality, &v.Status, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query vulnerability by name: %w", err)
	}
	return v, nil
}

func (s *Store) ListVulnerabilitiesByProject(ctx context.Context, projectID int64) ([]Vulnerability, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, name, description, criticality, status, created_at, updated_at
		FROM vulnerabilities WHERE project_id = ? ORDER BY id
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}
	defer rows.Close()

	out := []Vulnerability{}
	for rows.Next() {
		var v Vulnerability
		if err := rows.Scan(&v.ID, &v.ProjectID, &v.Name, &v.Description, &v.Criticality, &v.Status, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan vulnerability: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) DeleteVulnerability(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete vulnerability: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteVulnerabilitiesByProject(ctx context.Context, projectID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM vulnerabilities WHERE project_id = ?`, projectID)
	if err != nil {
		return 0, fmt.Errorf("delete vulnerabilities by project: %w", err)
	}
	return res.RowsAffected()
}

// ── Evidence CRUD ───────────────────────────────────────────────────

func (s *Store) CreateEvidence(ctx context.Context, e *Evidence) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO vuln_evidence (vuln_id, file_path, start_line, end_line, role, category, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, e.VulnID, e.FilePath, e.StartLine, e.EndLine, e.Role, e.Category, e.Severity)
	if err != nil {
		return 0, fmt.Errorf("insert evidence: %w", err)
	}
	return res.LastInsertId()
}

func (s *Store) ListEvidenceByProject(ctx context.Context, projectID int64) ([]Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.vuln_id, e.file_path, e.start_line, e.end_line, e.role, e.category, e.severity, e.created_at
		FROM vuln_evidence e
		JOIN vulnerabilities v ON v.id = e.vuln_id
		WHERE v.project_id = ?
		ORDER BY e.file_path, e.start_line
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()

	out := []Evidence{}
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.VulnID, &e.FilePath, &e.StartLine, &e.EndLine, &e.Role, &e.Category, &e.Severity, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListEvidenceByVuln(ctx context.Context, vulnID int64) ([]Evidence, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, vuln_id, file_path, start_line, end_line, role, category, severity, created_at
		FROM vuln_evidence WHERE vuln_id = ? ORDER BY file_path, start_line
	`, vulnID)
	if err != nil {
		return nil, fmt.Errorf("query evidence: %w", err)
	}
	defer rows.Close()

	out := []Evidence{}
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.VulnID, &e.FilePath, &e.StartLine, &e.EndLine, &e.Role, &e.Category, &e.Severity, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── CWE set ─────────────────────────────────────────────────────────

func (s *Store) AddVulnCWE(ctx context.Context, vulnID int64, cweID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO vuln_cwes (vuln_id, cwe_id) VALUES (?, ?)
	`, vulnID, cweID)
	if err != nil {
		return fmt.Errorf("insert vuln cwe: %w", err)
	}
	return nil
}

// ListVulnCWEs returns the acceptable CWE set per vulnerability for a
// project. Map[vulnID][]cweString — the matcher turns these into a
// normalized-int set and checks finding CWEs against it.
func (s *Store) ListVulnCWEs(ctx context.Context, projectID int64) (map[int64][]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.vuln_id, c.cwe_id
		FROM vuln_cwes c
		JOIN vulnerabilities v ON v.id = c.vuln_id
		WHERE v.project_id = ?
		ORDER BY c.vuln_id, c.cwe_id
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query vuln cwes: %w", err)
	}
	defer rows.Close()

	out := map[int64][]string{}
	for rows.Next() {
		var vid int64
		var cwe string
		if err := rows.Scan(&vid, &cwe); err != nil {
			return nil, fmt.Errorf("scan vuln cwe: %w", err)
		}
		out[vid] = append(out[vid], cwe)
	}
	return out, rows.Err()
}

// ── Annotators ──────────────────────────────────────────────────────

func (s *Store) AddVulnAnnotator(ctx context.Context, vulnID int64, annotatedBy string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO vuln_annotators (vuln_id, annotated_by) VALUES (?, ?)
	`, vulnID, annotatedBy)
	if err != nil {
		return fmt.Errorf("insert vuln annotator: %w", err)
	}
	return nil
}

// VulnConsensus returns how many distinct annotators agree each
// vulnerability exists. 1 = single annotator's call; 3 = strong
// consensus. Compare's --min-consensus filter reads this.
func (s *Store) VulnConsensus(ctx context.Context, projectID int64) (map[int64]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.id, COUNT(a.annotated_by)
		FROM vulnerabilities v
		LEFT JOIN vuln_annotators a ON a.vuln_id = v.id
		WHERE v.project_id = ?
		GROUP BY v.id
	`, projectID)
	if err != nil {
		return nil, fmt.Errorf("query consensus: %w", err)
	}
	defer rows.Close()

	out := map[int64]int{}
	for rows.Next() {
		var vid int64
		var n int
		if err := rows.Scan(&vid, &n); err != nil {
			return nil, fmt.Errorf("scan consensus: %w", err)
		}
		out[vid] = n
	}
	return out, rows.Err()
}

// ── Bulk import ─────────────────────────────────────────────────────

// BulkCreateVulnerabilities inserts a set of vulnerabilities with their
// evidence, CWEs, and annotators in one transaction. This is the
// new-format import path — the old AnnotationJSON format goes through
// the compat shim's BulkCreateAnnotations instead.
func (s *Store) BulkCreateVulnerabilities(ctx context.Context, vulns []VulnWithDetail) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	vStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vulnerabilities (project_id, name, description, criticality, status)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare vuln: %w", err)
	}
	defer vStmt.Close()

	eStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO vuln_evidence (vuln_id, file_path, start_line, end_line, role, category, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare evidence: %w", err)
	}
	defer eStmt.Close()

	cStmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO vuln_cwes (vuln_id, cwe_id) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare cwe: %w", err)
	}
	defer cStmt.Close()

	aStmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO vuln_annotators (vuln_id, annotated_by) VALUES (?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare annotator: %w", err)
	}
	defer aStmt.Close()

	for i := range vulns {
		v := &vulns[i]
		res, err := vStmt.ExecContext(ctx, v.ProjectID, v.Name, v.Description, v.Criticality, v.Status)
		if err != nil {
			return fmt.Errorf("insert vuln %q: %w", v.Name, err)
		}
		vid, _ := res.LastInsertId()
		v.ID = vid

		for j := range v.Evidence {
			e := &v.Evidence[j]
			if _, err := eStmt.ExecContext(ctx, vid, e.FilePath, e.StartLine, e.EndLine, e.Role, e.Category, e.Severity); err != nil {
				return fmt.Errorf("insert evidence for %q at %s:%d: %w", v.Name, e.FilePath, e.StartLine, err)
			}
		}
		for _, c := range v.CWEs {
			if _, err := cStmt.ExecContext(ctx, vid, c); err != nil {
				return fmt.Errorf("insert cwe %s for %q: %w", c, v.Name, err)
			}
		}
		for _, a := range v.Annotators {
			if _, err := aStmt.ExecContext(ctx, vid, a); err != nil {
				return fmt.Errorf("insert annotator %s for %q: %w", a, v.Name, err)
			}
		}
	}

	return tx.Commit()
}
