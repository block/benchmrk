package experiment

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/block/benchmrk/internal/analysis"
	scannerPkg "github.com/block/benchmrk/internal/scanner"
	"github.com/block/benchmrk/internal/store"
)

// mockStore provides a mock implementation of the Store interface for testing.
type mockStore struct {
	experiments       map[int64]*store.Experiment
	scanners          map[int64]*store.Scanner
	projects          map[int64]*store.CorpusProject
	runs              map[int64]*store.Run
	experimentScanner map[int64][]int64 // experimentID -> []scannerID
	experimentProject map[int64][]int64 // experimentID -> []projectID
	nextID            int64
}

func newMockStore() *mockStore {
	return &mockStore{
		experiments:       make(map[int64]*store.Experiment),
		scanners:          make(map[int64]*store.Scanner),
		projects:          make(map[int64]*store.CorpusProject),
		runs:              make(map[int64]*store.Run),
		experimentScanner: make(map[int64][]int64),
		experimentProject: make(map[int64][]int64),
		nextID:            1,
	}
}

func (m *mockStore) getNextID() int64 {
	id := m.nextID
	m.nextID++
	return id
}

func (m *mockStore) CreateExperiment(ctx context.Context, e *store.Experiment) (int64, error) {
	id := m.getNextID()
	e.ID = id
	e.CreatedAt = time.Now()
	m.experiments[id] = e
	return id, nil
}

func (m *mockStore) GetExperiment(ctx context.Context, id int64) (*store.Experiment, error) {
	e, ok := m.experiments[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return e, nil
}

func (m *mockStore) ListExperiments(ctx context.Context) ([]store.Experiment, error) {
	result := make([]store.Experiment, 0, len(m.experiments))
	for _, e := range m.experiments {
		result = append(result, *e)
	}
	return result, nil
}

func (m *mockStore) DeleteExperiment(ctx context.Context, id int64) error {
	if _, ok := m.experiments[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.experiments, id)
	delete(m.experimentScanner, id)
	delete(m.experimentProject, id)
	return nil
}

func (m *mockStore) AddScannerToExperiment(ctx context.Context, experimentID, scannerID int64) error {
	m.experimentScanner[experimentID] = append(m.experimentScanner[experimentID], scannerID)
	return nil
}

func (m *mockStore) AddProjectToExperiment(ctx context.Context, experimentID, projectID int64) error {
	m.experimentProject[experimentID] = append(m.experimentProject[experimentID], projectID)
	return nil
}

func (m *mockStore) ListExperimentScanners(ctx context.Context, experimentID int64) ([]store.Scanner, error) {
	ids := m.experimentScanner[experimentID]
	result := make([]store.Scanner, 0, len(ids))
	for _, id := range ids {
		if sc, ok := m.scanners[id]; ok {
			result = append(result, *sc)
		}
	}
	return result, nil
}

func (m *mockStore) ListExperimentProjects(ctx context.Context, experimentID int64) ([]store.CorpusProject, error) {
	ids := m.experimentProject[experimentID]
	result := make([]store.CorpusProject, 0, len(ids))
	for _, id := range ids {
		if p, ok := m.projects[id]; ok {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (m *mockStore) GetScanner(ctx context.Context, id int64) (*store.Scanner, error) {
	sc, ok := m.scanners[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return sc, nil
}

func (m *mockStore) GetProject(ctx context.Context, id int64) (*store.CorpusProject, error) {
	p, ok := m.projects[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return p, nil
}

func (m *mockStore) CreateRun(ctx context.Context, r *store.Run) (int64, error) {
	id := m.getNextID()
	r.ID = id
	r.CreatedAt = time.Now()
	m.runs[id] = r
	return id, nil
}

func (m *mockStore) GetRun(ctx context.Context, id int64) (*store.Run, error) {
	r, ok := m.runs[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return r, nil
}

func (m *mockStore) ListRunsByExperiment(ctx context.Context, experimentID int64) ([]store.Run, error) {
	result := []store.Run{}
	for _, r := range m.runs {
		if r.ExperimentID == experimentID {
			result = append(result, *r)
		}
	}
	return result, nil
}

func (m *mockStore) ListPendingRuns(ctx context.Context, experimentID int64) ([]store.Run, error) {
	result := []store.Run{}
	for _, r := range m.runs {
		if r.ExperimentID == experimentID && (r.Status == store.RunStatusPending || r.Status == store.RunStatusFailed) {
			result = append(result, *r)
		}
	}
	return result, nil
}

func (m *mockStore) ListRunsByScannerProject(ctx context.Context, scannerID, projectID int64) ([]store.Run, error) {
	result := []store.Run{}
	for _, r := range m.runs {
		if r.ScannerID == scannerID && r.ProjectID == projectID {
			result = append(result, *r)
		}
	}
	return result, nil
}

func (m *mockStore) UpdateRunStatus(ctx context.Context, id int64, status store.RunStatus, startedAt, completedAt sql.NullTime, durationMs, memoryPeakBytes sql.NullInt64, sarifPath, logPath, errorMessage sql.NullString) error {
	r, ok := m.runs[id]
	if !ok {
		return store.ErrNotFound
	}
	r.Status = status
	r.StartedAt = startedAt
	r.CompletedAt = completedAt
	r.DurationMs = durationMs
	r.MemoryPeakBytes = memoryPeakBytes
	r.SarifPath = sarifPath
	r.LogPath = logPath
	r.ErrorMessage = errorMessage
	return nil
}

// Helper to add scanner to mock store
func (m *mockStore) addScanner(name, version, image string) int64 {
	id := m.getNextID()
	m.scanners[id] = &store.Scanner{
		ID:          id,
		Name:        name,
		Version:     version,
		DockerImage: image,
		CreatedAt:   time.Now(),
	}
	return id
}

// Helper to add project to mock store
func (m *mockStore) addProject(name, path string) int64 {
	id := m.getNextID()
	m.projects[id] = &store.CorpusProject{
		ID:        id,
		Name:      name,
		LocalPath: path,
		CreatedAt: time.Now(),
	}
	return id
}

// mockScannerService provides a mock implementation of ScannerService.
// It simulates the real scanner.Service.Scan() behavior: when RunID is set,
// it updates the existing run in the store; otherwise it creates a new one.
type mockScannerService struct {
	scanCount     int32
	shouldFail    bool
	failOnScanner string
	store         *mockStore
}

func (m *mockScannerService) Scan(ctx context.Context, scannerName, projectName string, opts scannerPkg.ScanOptions) (*store.Run, error) {
	atomic.AddInt32(&m.scanCount, 1)
	if m.shouldFail || (m.failOnScanner != "" && m.failOnScanner == scannerName) {
		// Real Scan() marks the run as failed in the store, not returning an error
		if opts.RunID > 0 && m.store != nil {
			now := sql.NullTime{Time: time.Now(), Valid: true}
			errMsg := sql.NullString{String: "scan failed", Valid: true}
			m.store.UpdateRunStatus(ctx, opts.RunID, store.RunStatusFailed, now, now, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, errMsg)
			r, _ := m.store.GetRun(ctx, opts.RunID)
			return r, nil
		}
		return &store.Run{Status: store.RunStatusFailed}, nil
	}
	// Simulate real Scan() updating the existing run to completed
	if opts.RunID > 0 && m.store != nil {
		now := sql.NullTime{Time: time.Now(), Valid: true}
		m.store.UpdateRunStatus(ctx, opts.RunID, store.RunStatusCompleted, now, now, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, sql.NullString{})
		r, _ := m.store.GetRun(ctx, opts.RunID)
		return r, nil
	}
	return &store.Run{Status: store.RunStatusCompleted}, nil
}

// mockAnalysisService provides a mock implementation of AnalysisService.
type mockAnalysisService struct {
	analyzeCount int32
}

func (m *mockAnalysisService) AnalyzeRun(ctx context.Context, runID int64) (*analysis.Metrics, error) {
	atomic.AddInt32(&m.analyzeCount, 1)
	return &analysis.Metrics{}, nil
}

func TestNewService(t *testing.T) {
	ms := newMockStore()

	svc, err := NewService(ms, nil, nil)
	if err != nil {
		t.Fatalf("NewService() failed: %v", err)
	}
	if svc == nil {
		t.Error("NewService() returned nil")
	}
}

func TestNewServiceRequiresStore(t *testing.T) {
	_, err := NewService(nil, nil, nil)
	if err == nil {
		t.Error("NewService(nil) should return error")
	}
}

func TestCreateExperimentGeneratesCorrectNumberOfRuns(t *testing.T) {
	ms := newMockStore()
	scanner1 := ms.addScanner("semgrep", "1.0", "semgrep:1.0")
	scanner2 := ms.addScanner("gosec", "2.0", "gosec:2.0")
	project1 := ms.addProject("proj1", "/tmp/proj1")
	project2 := ms.addProject("proj2", "/tmp/proj2")
	project3 := ms.addProject("proj3", "/tmp/proj3")

	svc, _ := NewService(ms, nil, nil)

	iterations := 3
	scannerIDs := []int64{scanner1, scanner2}
	projectIDs := []int64{project1, project2, project3}

	exp, err := svc.Create(context.Background(), "test-exp", "desc", scannerIDs, projectIDs, iterations)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	runs, _ := ms.ListRunsByExperiment(context.Background(), exp.ID)
	expectedRuns := len(scannerIDs) * len(projectIDs) * iterations // 2 * 3 * 3 = 18
	if len(runs) != expectedRuns {
		t.Errorf("Create() generated %d runs, want %d", len(runs), expectedRuns)
	}

	// Verify all runs are pending
	for _, r := range runs {
		if r.Status != store.RunStatusPending {
			t.Errorf("Run status = %q, want %q", r.Status, store.RunStatusPending)
		}
	}
}

func TestCreateExperimentValidatesScannerIDs(t *testing.T) {
	ms := newMockStore()
	ms.addScanner("valid", "1.0", "valid:1.0")
	project := ms.addProject("proj", "/tmp/proj")

	svc, _ := NewService(ms, nil, nil)

	_, err := svc.Create(context.Background(), "test", "desc", []int64{999}, []int64{project}, 1)
	if err == nil {
		t.Error("Create() should fail with invalid scanner ID")
	}
	if !errors.Is(err, store.ErrNotFound) && err.Error() != "scanner 999 not found" {
		t.Logf("Got error: %v (expected scanner not found)", err)
	}
}

func TestCreateExperimentValidatesProjectIDs(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("valid", "1.0", "valid:1.0")
	ms.addProject("valid", "/tmp/valid")

	svc, _ := NewService(ms, nil, nil)

	_, err := svc.Create(context.Background(), "test", "desc", []int64{scanner}, []int64{999}, 1)
	if err == nil {
		t.Error("Create() should fail with invalid project ID")
	}
}

func TestCreateExperimentZeroIterationsCreatesNoRuns(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	svc, _ := NewService(ms, nil, nil)

	exp, err := svc.Create(context.Background(), "zero-iter", "desc", []int64{scanner}, []int64{project}, 0)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	runs, _ := ms.ListRunsByExperiment(context.Background(), exp.ID)
	if len(runs) != 0 {
		t.Errorf("Create() with 0 iterations generated %d runs, want 0", len(runs))
	}
}

func TestExecuteProcessesAllPendingRuns(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "exec-test", "", []int64{scanner}, []int64{project}, 3)

	err := svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	if mockScanner.scanCount != 3 {
		t.Errorf("Execute() called scanner %d times, want 3", mockScanner.scanCount)
	}
}

func TestExecuteRespectsConcurrencyLimit(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	// Create 5 runs
	exp, _ := svc.Create(context.Background(), "conc-test", "", []int64{scanner}, []int64{project}, 5)

	// Execute with concurrency=1 (sequential)
	err := svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	// All runs should complete
	status, _ := svc.Status(context.Background(), exp.ID)
	if status.Completed != 5 {
		t.Errorf("Execute() completed %d runs, want 5", status.Completed)
	}
}

func TestExecuteUpdatesRunStatusToRunningThenCompleted(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "status-test", "", []int64{scanner}, []int64{project}, 1)

	_ = svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})

	runs, _ := ms.ListRunsByExperiment(context.Background(), exp.ID)
	for _, r := range runs {
		if r.Status != store.RunStatusCompleted {
			t.Errorf("Run status = %q, want %q", r.Status, store.RunStatusCompleted)
		}
		if !r.StartedAt.Valid {
			t.Error("StartedAt should be set")
		}
		if !r.CompletedAt.Valid {
			t.Error("CompletedAt should be set")
		}
	}
}

func TestExecuteMarksRunFailedOnScannerError(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("failing", "1.0", "failing:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{shouldFail: true, store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "fail-test", "", []int64{scanner}, []int64{project}, 2)

	// Execute should not return error (failed runs don't block)
	err := svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})
	if err != nil {
		t.Logf("Execute() returned error: %v (expected for aggregated failures)", err)
	}

	status, _ := svc.Status(context.Background(), exp.ID)
	if status.Failed != 2 {
		t.Errorf("Expected 2 failed runs, got %d", status.Failed)
	}
}

func TestResumeSkipsCompletedRuns(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "resume-test", "", []int64{scanner}, []int64{project}, 3)

	// Execute all runs
	_ = svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})

	initialScanCount := mockScanner.scanCount

	// Resume should not run any more scans
	_ = svc.Resume(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})

	if mockScanner.scanCount != initialScanCount {
		t.Errorf("Resume() ran %d additional scans, want 0", mockScanner.scanCount-initialScanCount)
	}
}

func TestResumeRetriesFailedRuns(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{shouldFail: true, store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "retry-test", "", []int64{scanner}, []int64{project}, 2)

	// First run - all fail
	_ = svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})

	// Now make scanner succeed
	mockScanner.shouldFail = false
	mockScanner.scanCount = 0

	// Resume should retry failed runs
	_ = svc.Resume(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})

	if mockScanner.scanCount != 2 {
		t.Errorf("Resume() retried %d runs, want 2", mockScanner.scanCount)
	}

	status, _ := svc.Status(context.Background(), exp.ID)
	if status.Completed != 2 {
		t.Errorf("After resume, completed = %d, want 2", status.Completed)
	}
}

func TestStatusReturnsCorrectCounts(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	svc, _ := NewService(ms, nil, nil)

	exp, _ := svc.Create(context.Background(), "status-test", "", []int64{scanner}, []int64{project}, 5)

	// Manually update some run statuses
	runs, _ := ms.ListRunsByExperiment(context.Background(), exp.ID)
	ms.UpdateRunStatus(context.Background(), runs[0].ID, store.RunStatusRunning, sql.NullTime{}, sql.NullTime{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, sql.NullString{})
	ms.UpdateRunStatus(context.Background(), runs[1].ID, store.RunStatusCompleted, sql.NullTime{}, sql.NullTime{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, sql.NullString{})
	ms.UpdateRunStatus(context.Background(), runs[2].ID, store.RunStatusCompleted, sql.NullTime{}, sql.NullTime{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, sql.NullString{})
	ms.UpdateRunStatus(context.Background(), runs[3].ID, store.RunStatusFailed, sql.NullTime{}, sql.NullTime{}, sql.NullInt64{}, sql.NullInt64{}, sql.NullString{}, sql.NullString{}, sql.NullString{})
	// runs[4] stays pending

	status, err := svc.Status(context.Background(), exp.ID)
	if err != nil {
		t.Fatalf("Status() failed: %v", err)
	}

	if status.TotalRuns != 5 {
		t.Errorf("TotalRuns = %d, want 5", status.TotalRuns)
	}
	if status.Pending != 1 {
		t.Errorf("Pending = %d, want 1", status.Pending)
	}
	if status.Running != 1 {
		t.Errorf("Running = %d, want 1", status.Running)
	}
	if status.Completed != 2 {
		t.Errorf("Completed = %d, want 2", status.Completed)
	}
	if status.Failed != 1 {
		t.Errorf("Failed = %d, want 1", status.Failed)
	}
}

func TestAllRunsFailExperimentStillCompletes(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{shouldFail: true, store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "all-fail", "", []int64{scanner}, []int64{project}, 3)

	// Execute should complete (return error but not hang)
	done := make(chan bool)
	go func() {
		_ = svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 2})
		done <- true
	}()

	select {
	case <-done:
		// Good, completed
	case <-time.After(5 * time.Second):
		t.Fatal("Execute() deadlocked when all runs fail")
	}

	status, _ := svc.Status(context.Background(), exp.ID)
	if status.Failed != 3 {
		t.Errorf("Failed = %d, want 3", status.Failed)
	}
}

func TestExecuteWithConcurrencyOne(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	mockScanner := &mockScannerService{store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "seq-test", "", []int64{scanner}, []int64{project}, 5)

	err := svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1})
	if err != nil {
		t.Fatalf("Execute(concurrency=1) failed: %v", err)
	}

	if mockScanner.scanCount != 5 {
		t.Errorf("scanCount = %d, want 5", mockScanner.scanCount)
	}
}

func TestGetExperiment(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	svc, _ := NewService(ms, nil, nil)

	exp, _ := svc.Create(context.Background(), "get-test", "description", []int64{scanner}, []int64{project}, 1)

	got, err := svc.Get(context.Background(), exp.ID)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if got.Name != "get-test" {
		t.Errorf("Name = %q, want 'get-test'", got.Name)
	}
}

func TestListExperiments(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	svc, _ := NewService(ms, nil, nil)

	svc.Create(context.Background(), "exp1", "", []int64{scanner}, []int64{project}, 1)
	svc.Create(context.Background(), "exp2", "", []int64{scanner}, []int64{project}, 1)

	experiments, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(experiments) != 2 {
		t.Errorf("List() returned %d experiments, want 2", len(experiments))
	}
}

func TestDeleteExperiment(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	svc, _ := NewService(ms, nil, nil)

	exp, _ := svc.Create(context.Background(), "delete-test", "", []int64{scanner}, []int64{project}, 1)

	err := svc.Delete(context.Background(), exp.ID)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	_, err = svc.Get(context.Background(), exp.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get() after delete: error = %v, want ErrNotFound", err)
	}
}

func TestCreateExperimentRequiresName(t *testing.T) {
	ms := newMockStore()
	svc, _ := NewService(ms, nil, nil)

	_, err := svc.Create(context.Background(), "", "desc", nil, nil, 1)
	if err == nil {
		t.Error("Create() with empty name should fail")
	}
}

func TestCreateExperimentRejectsNegativeIterations(t *testing.T) {
	ms := newMockStore()
	svc, _ := NewService(ms, nil, nil)

	_, err := svc.Create(context.Background(), "test", "desc", nil, nil, -1)
	if err == nil {
		t.Error("Create() with negative iterations should fail")
	}
}

func TestExecuteRun_WithReuse_FindsCompletedRun(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	// Create a prior completed run with a valid SarifPath
	tmpDir := t.TempDir()
	sarifFile := tmpDir + "/results.sarif"
	os.WriteFile(sarifFile, []byte(`{"version":"2.1.0","runs":[]}`), 0644)

	priorRun := &store.Run{
		ScannerID: scanner,
		ProjectID: project,
		Status:    store.RunStatusCompleted,
		SarifPath: sql.NullString{String: sarifFile, Valid: true},
	}
	ms.CreateRun(context.Background(), priorRun)

	// Create scanner service mock that tracks import path usage
	mockScanner := &mockScannerService{store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	// Create experiment (generates new pending runs)
	exp, _ := svc.Create(context.Background(), "reuse-test", "", []int64{scanner}, []int64{project}, 1)

	// Execute with reuse enabled
	err := svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1, ReuseRuns: true})
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	// Scanner should still have been called (the reuse just sets ImportPath on ScanOptions)
	if mockScanner.scanCount != 1 {
		t.Errorf("Expected scanner to be called once, got %d", mockScanner.scanCount)
	}
}

func TestExecuteRun_WithReuse_NoMatch_FallsBack(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	// No prior completed runs exist
	mockScanner := &mockScannerService{store: ms}
	svc, _ := NewService(ms, mockScanner, nil)

	exp, _ := svc.Create(context.Background(), "no-reuse-test", "", []int64{scanner}, []int64{project}, 1)

	// Execute with reuse enabled - should fall back to normal execution
	err := svc.Execute(context.Background(), exp.ID, ExecuteOptions{Concurrency: 1, ReuseRuns: true})
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	// Scanner should be called normally
	if mockScanner.scanCount != 1 {
		t.Errorf("Expected scanner to be called once, got %d", mockScanner.scanCount)
	}
}

func TestFindReusableRunOutput_SkipsSelf(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	tmpDir := t.TempDir()
	sarifFile := tmpDir + "/results.sarif"
	os.WriteFile(sarifFile, []byte(`{}`), 0644)

	// Create a single completed run
	run := &store.Run{
		ScannerID: scanner,
		ProjectID: project,
		Status:    store.RunStatusCompleted,
		SarifPath: sql.NullString{String: sarifFile, Valid: true},
	}
	ms.CreateRun(context.Background(), run)

	svc, _ := NewService(ms, nil, nil)

	// Searching with excludeRunID = the only run's ID should return empty
	result, err := svc.findReusableRunOutput(context.Background(), scanner, project, run.ID)
	if err != nil {
		t.Fatalf("findReusableRunOutput() failed: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty result when excluding the only match, got %q", result)
	}
}

func TestFindReusableRunOutput_SkipsMissingFiles(t *testing.T) {
	ms := newMockStore()
	scanner := ms.addScanner("s1", "1.0", "s1:1.0")
	project := ms.addProject("p1", "/tmp/p1")

	// Create a completed run with a non-existent file path
	run := &store.Run{
		ScannerID: scanner,
		ProjectID: project,
		Status:    store.RunStatusCompleted,
		SarifPath: sql.NullString{String: "/nonexistent/results.sarif", Valid: true},
	}
	ms.CreateRun(context.Background(), run)

	svc, _ := NewService(ms, nil, nil)

	result, err := svc.findReusableRunOutput(context.Background(), scanner, project, 0)
	if err != nil {
		t.Fatalf("findReusableRunOutput() failed: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty result for missing file, got %q", result)
	}
}
