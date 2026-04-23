package corpus

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/block/benchmrk/internal/store"
)

// VulnerabilityJSON is the post-010 import format. The top-level file
// is {"vulnerabilities": [...]} — the object wrapper is what
// distinguishes this from the legacy flat array.
//
// Example:
//
//	{
//	  "vulnerabilities": [
//	    {
//	      "name": "task-idor",
//	      "description": "Tasks resource lacks ownership checks on all handlers",
//	      "criticality": "must",
//	      "status": "valid",
//	      "cwes": ["CWE-639", "CWE-862", "CWE-863"],
//	      "annotated_by": ["alice", "bob"],
//	      "evidence": [
//	        {"file": "routes/api.js", "line": 42, "role": "sink",
//	         "category": "broken-access-control", "severity": "high"},
//	        {"file": "routes/tasks.js", "line": 88, "end": 94, "role": "sink",
//	         "category": "broken-access-control", "severity": "high"}
//	      ]
//	    }
//	  ]
//	}
//
// Design notes:
//   - cwes is a set — any one matches. Put every CWE a reasonable
//     scanner might report for this bug.
//   - annotated_by is how consensus is computed: len(annotated_by).
//   - evidence.category/severity are per-location because different
//     manifestations of the same vuln can have different severity
//     (DELETE usually outranks READ).
//   - criticality defaults to "should"; status defaults to "valid".
type VulnerabilityJSON struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Criticality string         `json:"criticality,omitempty"`
	Status      string         `json:"status,omitempty"`
	CWEs        []string       `json:"cwes,omitempty"`
	AnnotatedBy []string       `json:"annotated_by,omitempty"`
	Evidence    []EvidenceJSON `json:"evidence"`
}

type EvidenceJSON struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	End      *int   `json:"end,omitempty"`
	Role     string `json:"role,omitempty"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

// vulnFileEnvelope is the top-level shape. The "vulnerabilities" key is
// the format discriminator — ImportAnnotations peeks at the first
// non-whitespace byte, and if it's '{' (object) it tries this, if '['
// (array) it falls through to the legacy AnnotationJSON path.
type vulnFileEnvelope struct {
	Vulnerabilities []VulnerabilityJSON `json:"vulnerabilities"`
}

// importVulnerabilities is the new-format half of ImportAnnotations.
// Called after the caller has already looked up the project and read
// the file. Returns evidence-row count (not vuln count) so the
// "Imported N annotations" CLI message stays intuitive.
func (s *Service) importVulnerabilities(ctx context.Context, projectID int64, raw []byte, replace bool) (int, error) {
	var env vulnFileEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, fmt.Errorf("parse vulnerability JSON: %w", err)
	}
	if len(env.Vulnerabilities) == 0 {
		return 0, fmt.Errorf(`file has no "vulnerabilities" array (or it is empty); ` +
			`for the legacy flat-array format, the top-level JSON must start with '['`)
	}

	// Guardrail 1: in-file duplicates. Two vulns with the same name in
	// the same JSON is almost always a copy-paste error, and it
	// silently halves recall the same way the DB-collision case does —
	// one copy matches, one is a permanent phantom FN.
	seen := make(map[string]int, len(env.Vulnerabilities)) // name → first position
	for i, vj := range env.Vulnerabilities {
		if vj.Name == "" {
			continue // position-N error below handles this
		}
		if first, dup := seen[vj.Name]; dup {
			return 0, fmt.Errorf("vulnerability name %q appears twice (positions %d and %d).\n"+
				"  If these are the same bug at different locations, use one entry with multiple evidence[] rows.\n"+
				"  If they are genuinely different bugs, give them distinct names.",
				vj.Name, first+1, i+1)
		}
		seen[vj.Name] = i
	}

	// Guardrail 2: DB collision. Importing the same file twice without
	// --replace doubles every vuln. Each finding matches the lower-ID
	// copy (matcher's deterministic tiebreak), the higher-ID copy is
	// never satisfied, and recall quietly drops to ~half its real
	// value. The user sees "FN: jwt-alg-none" and assumes their
	// scanner is broken when it isn't.
	//
	// This only blocks overlap, not append — adding genuinely new
	// vulns alongside existing ones (e.g. hand-written annotations on
	// top of triage-promoted ones) is still fine.
	if !replace {
		existing, err := s.store.ListVulnerabilitiesByProject(ctx, projectID)
		if err != nil {
			return 0, fmt.Errorf("check for existing vulnerabilities: %w", err)
		}
		existingNames := make(map[string]bool, len(existing))
		for _, v := range existing {
			existingNames[v.Name] = true
		}
		var collisions []string
		for _, vj := range env.Vulnerabilities {
			if existingNames[vj.Name] {
				collisions = append(collisions, vj.Name)
			}
		}
		if len(collisions) > 0 {
			return 0, fmt.Errorf("%d vulnerability name(s) already exist in this project: %s\n"+
				"  Importing without --replace would create duplicates and silently halve recall.\n"+
				"  Re-run with --replace to overwrite, or remove the overlapping entries from the file.",
				len(collisions), sampleNames(collisions, 5))
		}
	}

	vulns := make([]store.VulnWithDetail, 0, len(env.Vulnerabilities))
	evidenceCount := 0
	for i, vj := range env.Vulnerabilities {
		if vj.Name == "" {
			return 0, fmt.Errorf("vulnerability %d: name is required", i+1)
		}
		if len(vj.Evidence) == 0 {
			return 0, fmt.Errorf("vulnerability %q: at least one evidence location required", vj.Name)
		}

		crit := vj.Criticality
		if crit == "" {
			crit = "should"
		}
		if crit != "must" && crit != "should" && crit != "may" {
			return 0, fmt.Errorf("vulnerability %q: criticality must be must|should|may, got %q", vj.Name, crit)
		}

		statusStr := vj.Status
		if statusStr == "" {
			statusStr = "valid"
		}
		typedStatus := store.AnnotationStatus(statusStr)
		if !store.IsValidAnnotationStatus(typedStatus) {
			return 0, fmt.Errorf("vulnerability %q: invalid status %q", vj.Name, statusStr)
		}

		ev := make([]store.Evidence, 0, len(vj.Evidence))
		for j, ej := range vj.Evidence {
			if ej.File == "" {
				return 0, fmt.Errorf("vulnerability %q evidence %d: file is required", vj.Name, j+1)
			}
			if ej.Line <= 0 {
				return 0, fmt.Errorf("vulnerability %q evidence %d (%s): line must be positive", vj.Name, j+1, ej.File)
			}
			if ej.Category == "" {
				return 0, fmt.Errorf("vulnerability %q evidence %d (%s:%d): category is required", vj.Name, j+1, ej.File, ej.Line)
			}
			if !isValidSeverity(ej.Severity) {
				return 0, fmt.Errorf("vulnerability %q evidence %d (%s:%d): invalid severity %q", vj.Name, j+1, ej.File, ej.Line, ej.Severity)
			}
			role := ej.Role
			if role == "" {
				role = "sink"
			}
			e := store.Evidence{
				FilePath: ej.File, StartLine: ej.Line,
				Role: role, Category: ej.Category, Severity: ej.Severity,
			}
			if ej.End != nil {
				e.EndLine = sql.NullInt64{Int64: int64(*ej.End), Valid: true}
			}
			ev = append(ev, e)
		}
		evidenceCount += len(ev)

		var desc sql.NullString
		if vj.Description != "" {
			desc = sql.NullString{String: vj.Description, Valid: true}
		}

		vulns = append(vulns, store.VulnWithDetail{
			Vulnerability: store.Vulnerability{
				ProjectID: projectID, Name: vj.Name, Description: desc,
				Criticality: crit, Status: statusStr,
			},
			Evidence:   ev,
			CWEs:       vj.CWEs,
			Annotators: vj.AnnotatedBy,
		})
	}

	if replace {
		if _, err := s.store.DeleteVulnerabilitiesByProject(ctx, projectID); err != nil {
			return 0, fmt.Errorf("clear existing vulnerabilities: %w", err)
		}
	}

	if err := s.store.BulkCreateVulnerabilities(ctx, vulns); err != nil {
		return 0, fmt.Errorf("bulk create: %w", err)
	}

	return evidenceCount, nil
}

// sampleNames renders up to limit names for an error message, with a
// "(+N more)" suffix when truncated. A 42-name collision list is
// overwhelming; 5 examples plus the count is enough to recognise
// "oh, that's my whole file."
func sampleNames(names []string, limit int) string {
	if len(names) <= limit {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:limit], ", ") + fmt.Sprintf(" (+%d more)", len(names)-limit)
}

// recordImport writes an annotation_sets row so the scorer hash stamped
// on runs can be traced back to the file and commit it came from.
// Best-effort: a failure here doesn't fail the import — the data is
// already in, and the history row is a nice-to-have.
func (s *Service) recordImport(ctx context.Context, projectID int64, sourcePath, format string) {
	hash, err := s.store.AnnotationHash(ctx, projectID)
	if err != nil {
		return // nothing to record if we can't hash
	}

	vulns, _ := s.store.ListVulnerabilitiesByProject(ctx, projectID)

	set := &store.AnnotationSet{
		ProjectID: projectID,
		Hash:      hash,
		VulnCount: len(vulns),
		Format:    format,
	}
	if sourcePath != "" {
		set.SourcePath = sql.NullString{String: sourcePath, Valid: true}
		if sha := gitSHAOf(sourcePath); sha != "" {
			set.GitSHA = sql.NullString{String: sha, Valid: true}
		}
	}

	_, _ = s.store.RecordAnnotationSet(ctx, set)
}

// gitSHAOf returns the commit hash the file is at, or "" if the file
// isn't tracked or git isn't available. Deliberately permissive: a
// dirty working tree still returns HEAD's SHA, because "approximately
// this commit" beats nothing. If the file has uncommitted edits, the
// annotation_hash will differ from what that commit would produce
// anyway — the SHA is a breadcrumb, not ground truth.
func gitSHAOf(path string) string {
	dir := filepath.Dir(path)
	// rev-parse HEAD is the cheapest way to get "what commit am I at."
	// log -1 --format=%H -- <file> would give the last commit that
	// touched THIS file, which is more precise but fails on untracked
	// files. HEAD is good enough for a breadcrumb.
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
