package store

import (
	"database/sql"
	"time"
)

// RunStatus is the lifecycle state of a scan run.
type RunStatus string

const (
	RunStatusPending   RunStatus = "pending"
	RunStatusRunning   RunStatus = "running"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
)

// ExecutionMode describes how a scanner is invoked.
type ExecutionMode string

const (
	ExecutionModeDocker ExecutionMode = "docker"
	ExecutionModeLocal  ExecutionMode = "local"
)

// Disposition is a human triage judgment on a finding.
type Disposition string

const (
	DispositionTP          Disposition = "tp"
	DispositionFP          Disposition = "fp"
	DispositionNeedsReview Disposition = "needs_review"
)

// AnnotationStatus is the validity state of a ground-truth annotation.
type AnnotationStatus string

const (
	AnnotationStatusValid    AnnotationStatus = "valid"
	AnnotationStatusInvalid  AnnotationStatus = "invalid"
	AnnotationStatusDisputed AnnotationStatus = "disputed"
)

// CorpusProject represents a project in the corpus that we scan.
type CorpusProject struct {
	ID        int64
	Name      string
	SourceURL sql.NullString
	LocalPath string
	Language  sql.NullString
	CommitSHA sql.NullString
	CreatedAt time.Time
}

// Annotation represents a ground-truth vulnerability annotation in a project.
type Annotation struct {
	ID          int64
	ProjectID   int64
	FilePath    string
	StartLine   int
	EndLine     sql.NullInt64
	CWEID       sql.NullString
	Category    string
	Severity    string
	Description sql.NullString
	Status      AnnotationStatus
	AnnotatedBy sql.NullString
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ValidAnnotationStatuses lists all allowed annotation status values.
var ValidAnnotationStatuses = []AnnotationStatus{AnnotationStatusValid, AnnotationStatusInvalid, AnnotationStatusDisputed}

// IsValidAnnotationStatus checks if a status string is valid.
func IsValidAnnotationStatus(status AnnotationStatus) bool {
	for _, s := range ValidAnnotationStatuses {
		if s == status {
			return true
		}
	}
	return false
}

// Scanner represents a registered SAST scanner.
type Scanner struct {
	ID             int64
	Name           string
	Version        string
	DockerImage    string
	ConfigJSON     sql.NullString
	ExecutionMode  ExecutionMode  // ExecutionModeDocker or ExecutionModeLocal
	ExecutablePath sql.NullString // path to local executable (when execution_mode = "local")
	CreatedAt      time.Time
}

// Experiment represents a benchmarking experiment configuration.
type Experiment struct {
	ID          int64
	Name        string
	Description sql.NullString
	Iterations  int
	CreatedAt   time.Time
}

// Run represents a single scan execution.
type Run struct {
	ID              int64
	ExperimentID    int64
	ScannerID       int64
	ProjectID       int64
	Iteration       int
	Status          RunStatus
	StartedAt       sql.NullTime
	CompletedAt     sql.NullTime
	DurationMs      sql.NullInt64
	MemoryPeakBytes sql.NullInt64
	SarifPath       sql.NullString
	LogPath         sql.NullString
	ErrorMessage    sql.NullString
	// Scorer pinning — stamped at MatchRun time, not experiment-run time.
	// The scorer that matters is the one that produced finding_matches.
	// NULL on rows scored before migration 009.
	MatcherVersion sql.NullString
	AnnotationHash sql.NullString
	CreatedAt      time.Time
}

// Finding represents a parsed finding from scanner output.
type Finding struct {
	ID          int64
	RunID       int64
	RuleID      sql.NullString
	FilePath    string
	StartLine   int
	EndLine     sql.NullInt64
	CWEID       sql.NullString
	Severity    sql.NullString
	Message     sql.NullString
	Snippet     sql.NullString
	Fingerprint sql.NullString
	CreatedAt   time.Time
}

// FindingMatch represents a match between a finding and a ground-truth annotation.
type FindingMatch struct {
	ID        int64
	FindingID int64
	// AnnotationID is stored in the evidence_id column post migration 010.
	// The Go name stays so the matcher, metrics, and analysis code keep
	// compiling — and semantically it IS still "the annotation this finding
	// matched" since evidence row IDs inherit from the old annotation IDs.
	// New code should think of this as an evidence ID; the name is compat.
	AnnotationID int64
	MatchType    string
	Confidence   sql.NullFloat64
	CreatedAt    time.Time
}

// FindingDisposition records a human triage judgment on an unmatched finding.
type FindingDisposition struct {
	ID          int64
	FindingID   int64
	Disposition Disposition
	Notes       sql.NullString
	ReviewedBy  sql.NullString
	CreatedAt   time.Time
}

// AnnotationGroup represents a logical grouping of related annotations.
type AnnotationGroup struct {
	ID        int64
	ProjectID int64
	Name      sql.NullString
	CreatedAt time.Time
}

// AnnotationGroupMember represents membership of an annotation in a group.
type AnnotationGroupMember struct {
	GroupID      int64
	AnnotationID int64
	Role         string // "source", "sink", "related"
}

// ValidGroupRoles lists allowed group member roles.
var ValidGroupRoles = []string{"source", "sink", "related"}

// IsValidGroupRole checks if a role string is valid.
func IsValidGroupRole(role string) bool {
	for _, r := range ValidGroupRoles {
		if r == role {
			return true
		}
	}
	return false
}

// ValidDispositions lists all allowed disposition values.
var ValidDispositions = []Disposition{DispositionTP, DispositionFP, DispositionNeedsReview}

// IsValidDisposition checks if a disposition string is valid.
func IsValidDisposition(d Disposition) bool {
	for _, v := range ValidDispositions {
		if v == d {
			return true
		}
	}
	return false
}
