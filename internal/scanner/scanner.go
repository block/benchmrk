package scanner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/block/benchmrk/internal/normalise"
	"github.com/block/benchmrk/internal/sarif"
	"github.com/block/benchmrk/internal/store"
)

// Store defines the interface for scanner persistence operations.
type Store interface {
	CreateScanner(ctx context.Context, sc *store.Scanner) (int64, error)
	GetScanner(ctx context.Context, id int64) (*store.Scanner, error)
	GetScannerByNameVersion(ctx context.Context, name, version string) (*store.Scanner, error)
	ListScanners(ctx context.Context) ([]store.Scanner, error)
	GetProject(ctx context.Context, id int64) (*store.CorpusProject, error)
	GetProjectByName(ctx context.Context, name string) (*store.CorpusProject, error)
	CreateRun(ctx context.Context, r *store.Run) (int64, error)
	GetRun(ctx context.Context, id int64) (*store.Run, error)
	UpdateRunStatus(ctx context.Context, id int64, status store.RunStatus, startedAt, completedAt sql.NullTime, durationMs, memoryPeakBytes sql.NullInt64, sarifPath, logPath, errorMessage sql.NullString) error
	BulkCreateFindings(ctx context.Context, findings []store.Finding) error
}

// Service provides scanner management and execution operations.
type Service struct {
	store        Store
	dockerRunner *DockerRunner
	localRunner  *LocalRunner
	scannersDir  string
	outputDir    string
	converters   *normalise.Registry
}

// ServiceConfig contains configuration for the scanner service.
type ServiceConfig struct {
	ScannersDir string
	OutputDir   string
	Converters  *normalise.Registry
}

// NewService creates a new scanner service.
func NewService(s Store, runner *DockerRunner, cfg ServiceConfig) (*Service, error) {
	if s == nil {
		return nil, fmt.Errorf("store is required")
	}
	scannersDir := cfg.ScannersDir
	if scannersDir == "" {
		scannersDir = "scanners"
	}
	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = "output"
	}
	converters := cfg.Converters
	if converters == nil {
		converters = normalise.NewDefaultRegistry()
	}
	return &Service{
		store:        s,
		dockerRunner: runner,
		localRunner:  NewLocalRunner(),
		scannersDir:  scannersDir,
		outputDir:    outputDir,
		converters:   converters,
	}, nil
}

// RegisterOptions contains options for registering a scanner.
type RegisterOptions struct {
	Name           string
	Version        string
	DockerImage    string
	ExecutionMode  string // "docker" or "local" (default: "docker")
	ExecutablePath string // required when execution_mode = "local"
	ConfigJSON     string
}

// Register creates a new scanner registration in the database.
func (s *Service) Register(ctx context.Context, opts RegisterOptions) (*store.Scanner, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("scanner name is required")
	}
	if opts.Version == "" {
		return nil, fmt.Errorf("scanner version is required")
	}

	executionMode := store.ExecutionMode(opts.ExecutionMode)
	if executionMode == "" {
		executionMode = store.ExecutionModeDocker
	}

	switch executionMode {
	case store.ExecutionModeDocker:
		if opts.DockerImage == "" {
			return nil, fmt.Errorf("docker image is required for docker execution mode")
		}
	case store.ExecutionModeLocal:
		if opts.ExecutablePath == "" {
			return nil, fmt.Errorf("executable path is required for local execution mode")
		}
	default:
		return nil, fmt.Errorf("invalid execution mode %q: must be 'docker' or 'local'", executionMode)
	}

	// Check for duplicate name+version
	existing, err := s.store.GetScannerByNameVersion(ctx, opts.Name, opts.Version)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("check existing scanner: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("scanner %s version %s already exists", opts.Name, opts.Version)
	}

	sc := &store.Scanner{
		Name:          opts.Name,
		Version:       opts.Version,
		DockerImage:   opts.DockerImage,
		ExecutionMode: executionMode,
	}
	if opts.ExecutablePath != "" {
		sc.ExecutablePath = sql.NullString{String: opts.ExecutablePath, Valid: true}
	}
	if opts.ConfigJSON != "" {
		sc.ConfigJSON = sql.NullString{String: opts.ConfigJSON, Valid: true}
	}

	id, err := s.store.CreateScanner(ctx, sc)
	if err != nil {
		return nil, fmt.Errorf("create scanner: %w", err)
	}

	return s.store.GetScanner(ctx, id)
}

// List returns all registered scanners.
func (s *Service) List(ctx context.Context) ([]store.Scanner, error) {
	scanners, err := s.store.ListScanners(ctx)
	if err != nil {
		return nil, fmt.Errorf("list scanners: %w", err)
	}
	return scanners, nil
}

// Build builds a Docker image for the specified scanner from its Dockerfile.
// If a prepare.sh script exists in the scanner directory, it is executed first
// to set up the build context (e.g., copying external source files).
func (s *Service) Build(ctx context.Context, scannerName string) error {
	if scannerName == "" {
		return fmt.Errorf("scanner name is required")
	}

	if s.dockerRunner == nil {
		return fmt.Errorf("docker runner not configured; cannot build images")
	}

	scannerDir := filepath.Join(s.scannersDir, scannerName)
	dockerfilePath := filepath.Join(scannerDir, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		return fmt.Errorf("dockerfile not found for scanner %s: %s", scannerName, dockerfilePath)
	}

	// Run prepare.sh if it exists (pre-build hook for setting up build context)
	prepareScript := filepath.Join(scannerDir, "prepare.sh")
	if _, err := os.Stat(prepareScript); err == nil {
		absPrepare, _ := filepath.Abs(prepareScript)
		absScannerDir, _ := filepath.Abs(scannerDir)
		cmd := exec.CommandContext(ctx, "bash", absPrepare)
		cmd.Dir = absScannerDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("prepare build context for %s: %w", scannerName, err)
		}
	}

	_, err := s.dockerRunner.BuildImage(ctx, scannerName, dockerfilePath)
	if err != nil {
		return fmt.Errorf("build scanner image: %w", err)
	}

	return nil
}

// ScanOptions contains options for running a scan.
type ScanOptions struct {
	ExperimentID   int64
	Iteration      int
	CPU            float64
	MemoryMB       int64
	TimeoutMinutes int
	// RunID, when set, reuses an existing run record instead of creating a new one.
	// Used by the experiment engine which pre-creates pending runs.
	RunID int64
	// ConfigOverrides allows per-run override of scanner configuration.
	// Fields set here take precedence over the scanner's registered config.
	ConfigOverrides *ScannerConfig
	// ImportPath is the path to a pre-existing output file. When set, Docker
	// execution is skipped and the file is imported directly.
	ImportPath string
	// FormatOverride overrides the scanner's configured output format for
	// imports (e.g., "sarif", "semgrep-json").
	FormatOverride string
}

// Scan orchestrates a complete scan: create run, execute container, parse SARIF, store findings.
func (s *Service) Scan(ctx context.Context, scannerName, projectName string, opts ScanOptions) (*store.Run, error) {
	if scannerName == "" {
		return nil, fmt.Errorf("scanner name is required")
	}
	if projectName == "" {
		return nil, fmt.Errorf("project name is required")
	}

	// Look up scanner by name (use latest version)
	scanners, err := s.store.ListScanners(ctx)
	if err != nil {
		return nil, fmt.Errorf("list scanners: %w", err)
	}

	var scanner *store.Scanner
	for i := range scanners {
		if scanners[i].Name == scannerName {
			scanner = &scanners[i]
			break
		}
	}
	if scanner == nil {
		return nil, fmt.Errorf("scanner not found: %s", scannerName)
	}

	// Parse scanner configuration
	scannerCfg, err := ParseScannerConfig(scanner.ConfigJSON.String)
	if err != nil {
		return nil, fmt.Errorf("parse scanner config: %w", err)
	}

	// Apply run-level overrides
	if opts.ConfigOverrides != nil {
		scannerCfg = scannerCfg.Merge(*opts.ConfigOverrides)
	}

	// Apply format override (used for imports with a different format than scanner default)
	if opts.FormatOverride != "" {
		scannerCfg.OutputFormat = opts.FormatOverride
	}

	// Look up project by name
	project, err := s.store.GetProjectByName(ctx, projectName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("project not found: %s", projectName)
		}
		return nil, fmt.Errorf("get project: %w", err)
	}

	// Use existing run record or create a new one
	now := time.Now()
	var run *store.Run
	var runID int64
	if opts.RunID > 0 {
		// Reuse pre-created run from experiment engine
		run, err = s.store.GetRun(ctx, opts.RunID)
		if err != nil {
			return nil, fmt.Errorf("get existing run %d: %w", opts.RunID, err)
		}
		runID = run.ID
		run.Status = store.RunStatusRunning
		run.StartedAt = sql.NullTime{Time: now, Valid: true}
		if err := s.store.UpdateRunStatus(ctx, runID, store.RunStatusRunning, run.StartedAt, sql.NullTime{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, sql.NullString{}); err != nil {
			return nil, fmt.Errorf("update run to running: %w", err)
		}
	} else {
		// Create new run record with 'running' status
		run = &store.Run{
			ExperimentID: opts.ExperimentID,
			ScannerID:    scanner.ID,
			ProjectID:    project.ID,
			Iteration:    opts.Iteration,
			Status:       store.RunStatusRunning,
			StartedAt:    sql.NullTime{Time: now, Valid: true},
		}
		runID, err = s.store.CreateRun(ctx, run)
		if err != nil {
			return nil, fmt.Errorf("create run: %w", err)
		}
		run.ID = runID
	}

	// Prepare output directory for this run, scoped by project and scanner to avoid stale data
	runOutputDir := filepath.Join(s.outputDir, project.Name, scanner.Name, fmt.Sprintf("run-%d", runID))
	// Remove any stale output from a previous run with the same ID
	_ = os.RemoveAll(runOutputDir)

	// Execute the scanner container
	runOpts := RunOptions{
		Image:          scanner.DockerImage,
		CorpusPath:     project.LocalPath,
		OutputDir:      runOutputDir,
		CPU:            opts.CPU,
		MemoryMB:       opts.MemoryMB,
		TimeoutMinutes: opts.TimeoutMinutes,
		Cmd:            scannerCfg.Cmd,
		Entrypoint:     scannerCfg.Entrypoint,
		OutputFile:     scannerCfg.ResolvedOutputFile(),
		EnvVars: map[string]string{
			"SCANNER_NAME":    scanner.Name,
			"SCANNER_VERSION": scanner.Version,
		},
	}
	// Merge scanner config env vars
	for k, v := range scannerCfg.Env {
		runOpts.EnvVars[k] = v
	}
	if project.Language.Valid {
		runOpts.EnvVars["TARGET_LANGUAGE"] = project.Language.String
	}

	var result *RunResult
	var runErr error
	if opts.ImportPath != "" {
		result, runErr = s.importFile(opts.ImportPath, runOutputDir, scannerCfg.ResolvedOutputFile())
	} else if scanner.ExecutionMode == store.ExecutionModeLocal {
		localOpts := LocalRunOptions{
			ExecutablePath: scanner.ExecutablePath.String,
			Args:           scannerCfg.Cmd,
			CorpusPath:     project.LocalPath,
			OutputDir:      runOutputDir,
			TimeoutMinutes: opts.TimeoutMinutes,
			EnvVars:        runOpts.EnvVars,
			OutputFile:     scannerCfg.ResolvedOutputFile(),
		}
		result, runErr = s.localRunner.Run(ctx, localOpts)
	} else if s.dockerRunner == nil {
		runErr = fmt.Errorf("docker runner not configured; use import mode or ensure Docker is available")
	} else {
		result, runErr = s.dockerRunner.Run(ctx, runOpts)
	}

	// Prepare update values
	completedAt := sql.NullTime{Time: time.Now(), Valid: true}
	var durationMs sql.NullInt64
	var memoryPeakBytes sql.NullInt64
	var sarifPath sql.NullString
	var logPath sql.NullString
	var errorMessage sql.NullString

	if result != nil {
		durationMs = sql.NullInt64{Int64: result.DurationMs, Valid: true}
		if result.MemoryPeakBytes > 0 {
			memoryPeakBytes = sql.NullInt64{Int64: result.MemoryPeakBytes, Valid: true}
		}
		if result.OutputPath != "" {
			sarifPath = sql.NullString{String: result.OutputPath, Valid: true}
		}
		// Write container logs to file for debugging
		if result.Logs != "" {
			logFile := filepath.Join(runOutputDir, "scan.log")
			if writeErr := os.WriteFile(logFile, []byte(result.Logs), 0644); writeErr == nil {
				logPath = sql.NullString{String: logFile, Valid: true}
			}
		}
	}

	// Handle run error or missing output
	if runErr != nil || result == nil || result.OutputPath == "" {
		status := store.RunStatusFailed
		var errMsg string
		if runErr != nil {
			errMsg = runErr.Error()
		} else {
			errMsg = "scanner produced no output"
		}
		errorMessage = sql.NullString{String: errMsg, Valid: true}

		if updateErr := s.store.UpdateRunStatus(ctx, runID, status, run.StartedAt, completedAt, durationMs, memoryPeakBytes, sarifPath, logPath, errorMessage); updateErr != nil {
			return nil, fmt.Errorf("update run status: %w", updateErr)
		}

		run.Status = status
		run.CompletedAt = completedAt
		run.LogPath = logPath
		run.ErrorMessage = errorMessage
		return run, nil
	}

	// Parse output and store findings
	findings, parseErr := s.parseOutputAndConvert(result.OutputPath, runID, scannerCfg.ResolvedOutputFormat(), project.LocalPath)
	if parseErr != nil {
		status := store.RunStatusFailed
		errorMessage = sql.NullString{String: fmt.Sprintf("parse output (%s): %v", scannerCfg.ResolvedOutputFormat(), parseErr), Valid: true}

		if updateErr := s.store.UpdateRunStatus(ctx, runID, status, run.StartedAt, completedAt, durationMs, memoryPeakBytes, sarifPath, logPath, errorMessage); updateErr != nil {
			return nil, fmt.Errorf("update run status: %w", updateErr)
		}

		run.Status = status
		run.CompletedAt = completedAt
		run.LogPath = logPath
		run.ErrorMessage = errorMessage
		return run, nil
	}

	// Store findings in bulk
	if len(findings) > 0 {
		if err := s.store.BulkCreateFindings(ctx, findings); err != nil {
			status := store.RunStatusFailed
			errorMessage = sql.NullString{String: fmt.Sprintf("store findings: %v", err), Valid: true}

			if updateErr := s.store.UpdateRunStatus(ctx, runID, status, run.StartedAt, completedAt, durationMs, memoryPeakBytes, sarifPath, logPath, errorMessage); updateErr != nil {
				return nil, fmt.Errorf("update run status: %w", updateErr)
			}

			run.Status = status
			run.CompletedAt = completedAt
			run.LogPath = logPath
			run.ErrorMessage = errorMessage
			return run, nil
		}
	}

	// Update run as completed successfully
	status := store.RunStatusCompleted
	if updateErr := s.store.UpdateRunStatus(ctx, runID, status, run.StartedAt, completedAt, durationMs, memoryPeakBytes, sarifPath, logPath, errorMessage); updateErr != nil {
		return nil, fmt.Errorf("update run status: %w", updateErr)
	}

	run.Status = status
	run.CompletedAt = completedAt
	run.DurationMs = durationMs
	run.MemoryPeakBytes = memoryPeakBytes
	run.SarifPath = sarifPath
	run.LogPath = logPath

	return run, nil
}

// parseOutputAndConvert reads scanner output and converts findings to store.Finding structs.
// Uses the converter registry to handle the output format specified in the scanner config.
func (s *Service) parseOutputAndConvert(outputPath string, runID int64, outputFormat string, projectRoot string) ([]store.Finding, error) {
	file, err := os.Open(outputPath)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}
	defer file.Close()

	// Convert output to SARIF report using the appropriate converter
	report, err := s.converters.Convert(outputFormat, file)
	if err != nil {
		return nil, fmt.Errorf("convert %s output: %w", outputFormat, err)
	}

	sarifFindings, err := sarif.ExtractFindings(report)
	if err != nil {
		return nil, fmt.Errorf("extract findings: %w", err)
	}

	storeFindings := make([]store.Finding, len(sarifFindings))
	for i, sf := range sarifFindings {
		storeFindings[i] = store.Finding{
			RunID:     runID,
			FilePath:  canonicalizeFindingPath(sf.FilePath, projectRoot),
			StartLine: sf.StartLine,
			Fingerprint: sql.NullString{
				String: sf.Fingerprint,
				Valid:  sf.Fingerprint != "",
			},
		}
		if sf.RuleID != "" {
			storeFindings[i].RuleID = sql.NullString{String: sf.RuleID, Valid: true}
		}
		if sf.EndLine > 0 {
			storeFindings[i].EndLine = sql.NullInt64{Int64: int64(sf.EndLine), Valid: true}
		}
		if sf.CWE != "" {
			storeFindings[i].CWEID = sql.NullString{String: sf.CWE, Valid: true}
		}
		if sf.Severity != "" {
			storeFindings[i].Severity = sql.NullString{String: sf.Severity, Valid: true}
		}
		if sf.Message != "" {
			storeFindings[i].Message = sql.NullString{String: sf.Message, Valid: true}
		}
		if sf.Snippet != "" {
			storeFindings[i].Snippet = sql.NullString{String: sf.Snippet, Valid: true}
		}
	}

	return storeFindings, nil
}

// canonicalizeFindingPath normalizes scanner-reported file paths into a stable
// project-relative form when possible.
//
// It handles common scanner path shapes:
//   - Docker mount paths under /target/
//   - Absolute local paths under the corpus project root
//   - file:// URIs
//
// If a path can't be relativized deterministically, it is preserved (cleaned).
func canonicalizeFindingPath(rawPath, projectRoot string) string {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return p
	}

	// Some scanners emit file:// URIs in SARIF artifact locations.
	if u, err := url.Parse(p); err == nil && strings.EqualFold(u.Scheme, "file") {
		if u.Path != "" {
			p = u.Path
		}
	}

	p = filepath.Clean(filepath.FromSlash(p))

	// Normalize paths reported from Dockerized scanners.
	dockerRoot := filepath.Clean(string(filepath.Separator) + "target")
	if p == dockerRoot {
		p = "."
	} else {
		withSep := dockerRoot + string(filepath.Separator)
		if strings.HasPrefix(p, withSep) {
			p = strings.TrimPrefix(p, withSep)
		}
	}

	// Strip leading ./ for consistency with annotations.
	if strings.HasPrefix(p, "."+string(filepath.Separator)) {
		p = strings.TrimPrefix(p, "."+string(filepath.Separator))
	}

	// Relativize absolute local paths to the project root when possible.
	if projectRoot != "" && filepath.IsAbs(p) {
		if absProjectRoot, err := filepath.Abs(projectRoot); err == nil {
			if rel, err := filepath.Rel(absProjectRoot, p); err == nil {
				rel = filepath.Clean(rel)
				if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
					p = rel
				}
			}
		}
	}

	return filepath.ToSlash(p)
}

// importFile copies a pre-existing output file into the run output directory,
// returning a RunResult compatible with the Docker execution path.
func (s *Service) importFile(importPath, outputDir, expectedFilename string) (*RunResult, error) {
	info, err := os.Stat(importPath)
	if err != nil {
		return nil, fmt.Errorf("import file not found: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("import path is a directory, not a file: %s", importPath)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	destPath := filepath.Join(outputDir, expectedFilename)
	data, err := os.ReadFile(importPath)
	if err != nil {
		return nil, fmt.Errorf("read import file: %w", err)
	}
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return nil, fmt.Errorf("write import file: %w", err)
	}

	return &RunResult{
		ExitCode:   0,
		OutputPath: destPath,
		Logs:       fmt.Sprintf("imported from %s", importPath),
	}, nil
}
