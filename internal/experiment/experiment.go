// Package experiment provides the experiment engine for orchestrating benchmarking experiments.
package experiment

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/block/benchmrk/internal/analysis"
	scannerPkg "github.com/block/benchmrk/internal/scanner"
	"github.com/block/benchmrk/internal/store"
)

// Store defines the store methods needed by the experiment service.
type Store interface {
	// Experiment CRUD
	CreateExperiment(ctx context.Context, e *store.Experiment) (int64, error)
	GetExperiment(ctx context.Context, id int64) (*store.Experiment, error)
	ListExperiments(ctx context.Context) ([]store.Experiment, error)
	DeleteExperiment(ctx context.Context, id int64) error

	// Experiment associations
	AddScannerToExperiment(ctx context.Context, experimentID, scannerID int64) error
	AddProjectToExperiment(ctx context.Context, experimentID, projectID int64) error
	ListExperimentScanners(ctx context.Context, experimentID int64) ([]store.Scanner, error)
	ListExperimentProjects(ctx context.Context, experimentID int64) ([]store.CorpusProject, error)

	// Scanner and project lookups
	GetScanner(ctx context.Context, id int64) (*store.Scanner, error)
	GetProject(ctx context.Context, id int64) (*store.CorpusProject, error)

	// Run management
	CreateRun(ctx context.Context, r *store.Run) (int64, error)
	GetRun(ctx context.Context, id int64) (*store.Run, error)
	ListRunsByExperiment(ctx context.Context, experimentID int64) ([]store.Run, error)
	ListPendingRuns(ctx context.Context, experimentID int64) ([]store.Run, error)
	UpdateRunStatus(ctx context.Context, id int64, status store.RunStatus, startedAt, completedAt sql.NullTime, durationMs, memoryPeakBytes sql.NullInt64, sarifPath, logPath, errorMessage sql.NullString) error
	ListRunsByScannerProject(ctx context.Context, scannerID, projectID int64) ([]store.Run, error)
}

// ScannerService defines the scanner service methods needed for execution.
type ScannerService interface {
	Scan(ctx context.Context, scannerName, projectName string, opts scannerPkg.ScanOptions) (*store.Run, error)
}

// AnalysisService defines the analysis service methods needed for post-run analysis.
type AnalysisService interface {
	AnalyzeRun(ctx context.Context, runID int64) (*analysis.Metrics, error)
}

// ProgressCallback is called to report execution progress.
// completed is the number of runs finished, total is the total number of runs,
// lastScanner and lastProject describe the most recently completed run.
type ProgressCallback func(completed, total int, lastScanner, lastProject, status string)

// Service provides experiment creation and execution operations.
type Service struct {
	store            Store
	scanner          ScannerService
	analysis         AnalysisService
	progressCallback ProgressCallback
}

// SetProgressCallback sets a callback function for progress updates during execution.
func (s *Service) SetProgressCallback(cb ProgressCallback) {
	s.progressCallback = cb
}

// NewService creates a new experiment service.
func NewService(s Store, scannerSvc ScannerService, analysisSvc AnalysisService) (*Service, error) {
	if s == nil {
		return nil, fmt.Errorf("store is required")
	}
	return &Service{
		store:    s,
		scanner:  scannerSvc,
		analysis: analysisSvc,
	}, nil
}

// ExperimentStatus contains status counts for an experiment.
type ExperimentStatus struct {
	ExperimentID int64
	Name         string
	TotalRuns    int
	Pending      int
	Running      int
	Completed    int
	Failed       int
}

// Create creates a new experiment with scanner and project associations, and generates all run records upfront.
func (s *Service) Create(ctx context.Context, name, description string, scannerIDs, projectIDs []int64, iterations int) (*store.Experiment, error) {
	if name == "" {
		return nil, fmt.Errorf("experiment name is required")
	}
	if iterations < 0 {
		return nil, fmt.Errorf("iterations must be non-negative")
	}

	// Validate all scanner IDs exist
	for _, scannerID := range scannerIDs {
		if _, err := s.store.GetScanner(ctx, scannerID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, fmt.Errorf("scanner %d not found", scannerID)
			}
			return nil, fmt.Errorf("validate scanner %d: %w", scannerID, err)
		}
	}

	// Validate all project IDs exist
	for _, projectID := range projectIDs {
		if _, err := s.store.GetProject(ctx, projectID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, fmt.Errorf("project %d not found", projectID)
			}
			return nil, fmt.Errorf("validate project %d: %w", projectID, err)
		}
	}

	// Create experiment record
	exp := &store.Experiment{
		Name:       name,
		Iterations: iterations,
	}
	if description != "" {
		exp.Description = sql.NullString{String: description, Valid: true}
	}

	expID, err := s.store.CreateExperiment(ctx, exp)
	if err != nil {
		return nil, fmt.Errorf("create experiment: %w", err)
	}

	// Link scanners to experiment
	for _, scannerID := range scannerIDs {
		if err := s.store.AddScannerToExperiment(ctx, expID, scannerID); err != nil {
			return nil, fmt.Errorf("link scanner %d: %w", scannerID, err)
		}
	}

	// Link projects to experiment
	for _, projectID := range projectIDs {
		if err := s.store.AddProjectToExperiment(ctx, expID, projectID); err != nil {
			return nil, fmt.Errorf("link project %d: %w", projectID, err)
		}
	}

	// Create all run records upfront (scanners × projects × iterations)
	for _, scannerID := range scannerIDs {
		for _, projectID := range projectIDs {
			for i := 1; i <= iterations; i++ {
				run := &store.Run{
					ExperimentID: expID,
					ScannerID:    scannerID,
					ProjectID:    projectID,
					Iteration:    i,
					Status:       store.RunStatusPending,
				}
				if _, err := s.store.CreateRun(ctx, run); err != nil {
					return nil, fmt.Errorf("create run (scanner=%d, project=%d, iter=%d): %w", scannerID, projectID, i, err)
				}
			}
		}
	}

	return s.store.GetExperiment(ctx, expID)
}

// ExecuteOptions configures experiment execution behavior.
type ExecuteOptions struct {
	Concurrency int
	ReuseRuns   bool // If true, reuse results from prior completed runs instead of re-executing.
}

// Execute runs all pending runs for an experiment.
func (s *Service) Execute(ctx context.Context, experimentID int64, opts ExecuteOptions) error {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}

	// Verify experiment exists
	exp, err := s.store.GetExperiment(ctx, experimentID)
	if err != nil {
		return fmt.Errorf("get experiment: %w", err)
	}

	// Get all runs for the experiment
	runs, err := s.store.ListRunsByExperiment(ctx, experimentID)
	if err != nil {
		return fmt.Errorf("list runs: %w", err)
	}

	// Filter to only pending runs
	var pendingRuns []store.Run
	for _, r := range runs {
		if r.Status == store.RunStatusPending {
			pendingRuns = append(pendingRuns, r)
		}
	}

	return s.executeRuns(ctx, exp, pendingRuns, opts)
}

// Resume resumes execution of an experiment, picking up pending and failed runs.
func (s *Service) Resume(ctx context.Context, experimentID int64, opts ExecuteOptions) error {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}

	// Verify experiment exists
	exp, err := s.store.GetExperiment(ctx, experimentID)
	if err != nil {
		return fmt.Errorf("get experiment: %w", err)
	}

	// Get pending and failed runs
	runs, err := s.store.ListPendingRuns(ctx, experimentID)
	if err != nil {
		return fmt.Errorf("list pending runs: %w", err)
	}

	return s.executeRuns(ctx, exp, runs, opts)
}

// executeRuns processes runs using a worker pool.
func (s *Service) executeRuns(ctx context.Context, exp *store.Experiment, runs []store.Run, opts ExecuteOptions) error {
	if len(runs) == 0 {
		return nil
	}

	// Build lookup maps for scanners and projects
	scanners, err := s.store.ListExperimentScanners(ctx, exp.ID)
	if err != nil {
		return fmt.Errorf("list experiment scanners: %w", err)
	}
	scannerByID := make(map[int64]store.Scanner)
	for _, sc := range scanners {
		scannerByID[sc.ID] = sc
	}

	projects, err := s.store.ListExperimentProjects(ctx, exp.ID)
	if err != nil {
		return fmt.Errorf("list experiment projects: %w", err)
	}
	projectByID := make(map[int64]store.CorpusProject)
	for _, p := range projects {
		projectByID[p.ID] = p
	}

	// Create work channel and error collection
	runChan := make(chan store.Run, len(runs))
	for _, r := range runs {
		runChan <- r
	}
	close(runChan)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var runErrors []error
	var completedCount int
	totalRuns := len(runs)

	// Start worker goroutines
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for run := range runChan {
				sc := scannerByID[run.ScannerID]
				project := projectByID[run.ProjectID]

				s.executeRun(ctx, run, scannerByID, projectByID, opts.ReuseRuns)

				// Read actual status from the store (Scan() updates it)
				status := store.RunStatusCompleted
				if updatedRun, err := s.store.GetRun(ctx, run.ID); err == nil {
					status = updatedRun.Status
				}

				mu.Lock()
				completedCount++
				if status == store.RunStatusFailed {
					runErrors = append(runErrors, fmt.Errorf("run %d: %s", run.ID, status))
				}
				// Report progress if callback is set
				if s.progressCallback != nil {
					s.progressCallback(completedCount, totalRuns, sc.Name, project.Name, string(status))
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if len(runErrors) > 0 {
		return fmt.Errorf("%d runs failed: %v", len(runErrors), runErrors[0])
	}

	return nil
}

// executeRun executes a single run: update status to running, invoke scanner, analyze, update status.
func (s *Service) executeRun(ctx context.Context, run store.Run, scannerByID map[int64]store.Scanner, projectByID map[int64]store.CorpusProject, reuseRuns bool) error {
	sc, ok := scannerByID[run.ScannerID]
	if !ok {
		return s.markRunFailed(ctx, run.ID, "scanner not found in experiment")
	}

	project, ok := projectByID[run.ProjectID]
	if !ok {
		return s.markRunFailed(ctx, run.ID, "project not found in experiment")
	}

	// Check if scanner service is available
	if s.scanner == nil {
		return s.markRunFailed(ctx, run.ID, "scanner service not configured")
	}

	// Build scan options — pass the pre-created RunID so Scan() reuses it
	opts := scannerPkg.ScanOptions{
		RunID:        run.ID,
		ExperimentID: run.ExperimentID,
		Iteration:    run.Iteration,
	}

	// If reuse is enabled, look for a completed run with the same scanner+project
	if reuseRuns {
		if importPath, err := s.findReusableRunOutput(ctx, run.ScannerID, run.ProjectID, run.ID); err == nil && importPath != "" {
			opts.ImportPath = importPath
		}
	}

	scanResult, scanErr := s.scanner.Scan(ctx, sc.Name, project.Name, opts)

	if scanErr != nil {
		// Scan() returns an error only for infrastructure failures (e.g. scanner not found).
		// Container failures are recorded in the run status by Scan() itself.
		return nil
	}

	// Run analysis if service is available and scan completed successfully
	if s.analysis != nil && scanResult != nil && scanResult.Status == store.RunStatusCompleted {
		if _, err := s.analysis.AnalyzeRun(ctx, scanResult.ID); err != nil {
			// Log but don't fail - analysis is optional
			_ = err
		}
	}

	return nil
}

// findReusableRunOutput searches for a completed run with the same scanner+project
// combination and returns its output path if available.
func (s *Service) findReusableRunOutput(ctx context.Context, scannerID, projectID, excludeRunID int64) (string, error) {
	runs, err := s.store.ListRunsByScannerProject(ctx, scannerID, projectID)
	if err != nil {
		return "", fmt.Errorf("list runs for reuse: %w", err)
	}

	// ListRunsByScannerProject returns results ordered by created_at DESC,
	// so the first completed run with a valid SarifPath is the most recent.
	for _, r := range runs {
		if r.ID == excludeRunID {
			continue
		}
		if r.Status == store.RunStatusCompleted && r.SarifPath.Valid && r.SarifPath.String != "" {
			if _, err := os.Stat(r.SarifPath.String); err == nil {
				return r.SarifPath.String, nil
			}
		}
	}

	return "", nil
}

// markRunFailed marks a run as failed with the given error message.
func (s *Service) markRunFailed(ctx context.Context, runID int64, errMsg string) error {
	now := sql.NullTime{Time: time.Now(), Valid: true}
	errorMessage := sql.NullString{String: errMsg, Valid: true}
	if err := s.store.UpdateRunStatus(ctx, runID, store.RunStatusFailed, now, now, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, errorMessage); err != nil {
		return fmt.Errorf("update status to failed: %w", err)
	}
	return nil
}

// Status returns the status counts for an experiment.
func (s *Service) Status(ctx context.Context, experimentID int64) (*ExperimentStatus, error) {
	exp, err := s.store.GetExperiment(ctx, experimentID)
	if err != nil {
		return nil, fmt.Errorf("get experiment: %w", err)
	}

	runs, err := s.store.ListRunsByExperiment(ctx, experimentID)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}

	status := &ExperimentStatus{
		ExperimentID: exp.ID,
		Name:         exp.Name,
		TotalRuns:    len(runs),
	}

	for _, r := range runs {
		switch r.Status {
		case store.RunStatusPending:
			status.Pending++
		case store.RunStatusRunning:
			status.Running++
		case store.RunStatusCompleted:
			status.Completed++
		case store.RunStatusFailed:
			status.Failed++
		}
	}

	return status, nil
}

// Get retrieves an experiment by ID with its associated scanners and projects.
func (s *Service) Get(ctx context.Context, id int64) (*store.Experiment, error) {
	return s.store.GetExperiment(ctx, id)
}

// List returns all experiments.
func (s *Service) List(ctx context.Context) ([]store.Experiment, error) {
	return s.store.ListExperiments(ctx)
}

// Delete removes an experiment by ID.
func (s *Service) Delete(ctx context.Context, id int64) error {
	return s.store.DeleteExperiment(ctx, id)
}
