package scanner

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/benchmrk/internal/store"
)

// writeOutputOnStart returns an onStart callback that writes content to the given filename
// in the container's /output mount directory, simulating scanner container output.
func writeOutputOnStart(filename, content string) func(config *ContainerConfig) {
	return func(config *ContainerConfig) {
		for _, m := range config.Mounts {
			if m.Target == "/output" {
				os.MkdirAll(m.Source, 0755)
				os.WriteFile(filepath.Join(m.Source, filename), []byte(content), 0644)
				return
			}
		}
	}
}

// mockStore implements Store interface for testing.
type mockStore struct {
	scanners []store.Scanner
	projects []store.CorpusProject
	runs     []store.Run
	findings []store.Finding

	createScannerErr      error
	getScannerErr         error
	getScannerByNameErr   error
	listScannersErr       error
	getProjectErr         error
	getProjectByNameErr   error
	createRunErr          error
	getRunErr             error
	updateRunStatusErr    error
	bulkCreateFindingsErr error

	lastCreatedScanner *store.Scanner
	lastCreatedRun     *store.Run
	lastUpdatedRunID   int64
	lastUpdatedStatus  store.RunStatus
	lastErrorMessage   string
}

func (m *mockStore) CreateScanner(ctx context.Context, sc *store.Scanner) (int64, error) {
	if m.createScannerErr != nil {
		return 0, m.createScannerErr
	}
	id := int64(len(m.scanners) + 1)
	sc.ID = id
	m.scanners = append(m.scanners, *sc)
	m.lastCreatedScanner = sc
	return id, nil
}

func (m *mockStore) GetScanner(ctx context.Context, id int64) (*store.Scanner, error) {
	if m.getScannerErr != nil {
		return nil, m.getScannerErr
	}
	for i := range m.scanners {
		if m.scanners[i].ID == id {
			return &m.scanners[i], nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) GetScannerByNameVersion(ctx context.Context, name, version string) (*store.Scanner, error) {
	if m.getScannerByNameErr != nil {
		return nil, m.getScannerByNameErr
	}
	for i := range m.scanners {
		if m.scanners[i].Name == name && m.scanners[i].Version == version {
			return &m.scanners[i], nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) ListScanners(ctx context.Context) ([]store.Scanner, error) {
	if m.listScannersErr != nil {
		return nil, m.listScannersErr
	}
	return m.scanners, nil
}

func (m *mockStore) GetProject(ctx context.Context, id int64) (*store.CorpusProject, error) {
	if m.getProjectErr != nil {
		return nil, m.getProjectErr
	}
	for i := range m.projects {
		if m.projects[i].ID == id {
			return &m.projects[i], nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) GetProjectByName(ctx context.Context, name string) (*store.CorpusProject, error) {
	if m.getProjectByNameErr != nil {
		return nil, m.getProjectByNameErr
	}
	for i := range m.projects {
		if m.projects[i].Name == name {
			return &m.projects[i], nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) CreateRun(ctx context.Context, r *store.Run) (int64, error) {
	if m.createRunErr != nil {
		return 0, m.createRunErr
	}
	id := int64(len(m.runs) + 1)
	r.ID = id
	m.runs = append(m.runs, *r)
	m.lastCreatedRun = r
	return id, nil
}

func (m *mockStore) GetRun(ctx context.Context, id int64) (*store.Run, error) {
	if m.getRunErr != nil {
		return nil, m.getRunErr
	}
	for i := range m.runs {
		if m.runs[i].ID == id {
			return &m.runs[i], nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) UpdateRunStatus(ctx context.Context, id int64, status store.RunStatus, startedAt, completedAt sql.NullTime, durationMs, memoryPeakBytes sql.NullInt64, sarifPath, logPath, errorMessage sql.NullString) error {
	if m.updateRunStatusErr != nil {
		return m.updateRunStatusErr
	}
	m.lastUpdatedRunID = id
	m.lastUpdatedStatus = status
	if errorMessage.Valid {
		m.lastErrorMessage = errorMessage.String
	}
	for i := range m.runs {
		if m.runs[i].ID == id {
			m.runs[i].Status = status
			m.runs[i].CompletedAt = completedAt
			m.runs[i].DurationMs = durationMs
			m.runs[i].MemoryPeakBytes = memoryPeakBytes
			m.runs[i].SarifPath = sarifPath
			m.runs[i].LogPath = logPath
			m.runs[i].ErrorMessage = errorMessage
			return nil
		}
	}
	return store.ErrNotFound
}

func (m *mockStore) BulkCreateFindings(ctx context.Context, findings []store.Finding) error {
	if m.bulkCreateFindingsErr != nil {
		return m.bulkCreateFindingsErr
	}
	m.findings = append(m.findings, findings...)
	return nil
}

func TestNewService(t *testing.T) {
	mockSt := &mockStore{}
	mockClient := &mockDockerClient{}
	runner, _ := NewDockerRunner(mockClient)

	t.Run("success", func(t *testing.T) {
		svc, err := NewService(mockSt, runner, ServiceConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})

	t.Run("nil store", func(t *testing.T) {
		_, err := NewService(nil, runner, ServiceConfig{})
		if err == nil || !strings.Contains(err.Error(), "store is required") {
			t.Errorf("expected 'store is required' error, got: %v", err)
		}
	})

	t.Run("nil runner allowed", func(t *testing.T) {
		svc, err := NewService(mockSt, nil, ServiceConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc == nil {
			t.Fatal("expected non-nil service")
		}
	})
}

func TestService_Register(t *testing.T) {
	t.Run("creates scanner in store", func(t *testing.T) {
		mockSt := &mockStore{}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{})

		sc, err := svc.Register(context.Background(), RegisterOptions{
			Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep/semgrep:1.0.0", ConfigJSON: `{"rules":"default"}`,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if sc.Name != "semgrep" {
			t.Errorf("expected name 'semgrep', got %q", sc.Name)
		}
		if sc.Version != "1.0.0" {
			t.Errorf("expected version '1.0.0', got %q", sc.Version)
		}
		if sc.DockerImage != "semgrep/semgrep:1.0.0" {
			t.Errorf("expected docker image 'semgrep/semgrep:1.0.0', got %q", sc.DockerImage)
		}
		if !sc.ConfigJSON.Valid || sc.ConfigJSON.String != `{"rules":"default"}` {
			t.Errorf("expected config JSON, got %v", sc.ConfigJSON)
		}

		if len(mockSt.scanners) != 1 {
			t.Errorf("expected 1 scanner in store, got %d", len(mockSt.scanners))
		}
	})

	t.Run("duplicate name+version returns error", func(t *testing.T) {
		mockSt := &mockStore{
			scanners: []store.Scanner{
				{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep/semgrep:1.0.0"},
			},
		}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{})

		_, err := svc.Register(context.Background(), RegisterOptions{
			Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep/semgrep:1.0.0",
		})
		if err == nil {
			t.Fatal("expected error for duplicate scanner")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected 'already exists' error, got: %v", err)
		}
	})

	t.Run("empty name returns error", func(t *testing.T) {
		mockSt := &mockStore{}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{})

		_, err := svc.Register(context.Background(), RegisterOptions{
			Version: "1.0.0", DockerImage: "image:latest",
		})
		if err == nil || !strings.Contains(err.Error(), "name is required") {
			t.Errorf("expected 'name is required' error, got: %v", err)
		}
	})

	t.Run("empty version returns error", func(t *testing.T) {
		mockSt := &mockStore{}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{})

		_, err := svc.Register(context.Background(), RegisterOptions{
			Name: "scanner", DockerImage: "image:latest",
		})
		if err == nil || !strings.Contains(err.Error(), "version is required") {
			t.Errorf("expected 'version is required' error, got: %v", err)
		}
	})

	t.Run("empty docker image returns error", func(t *testing.T) {
		mockSt := &mockStore{}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{})

		_, err := svc.Register(context.Background(), RegisterOptions{
			Name: "scanner", Version: "1.0.0",
		})
		if err == nil || !strings.Contains(err.Error(), "docker image is required") {
			t.Errorf("expected 'docker image is required' error, got: %v", err)
		}
	})
}

func TestService_List(t *testing.T) {
	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0"},
			{ID: 2, Name: "codeql", Version: "2.0.0"},
		},
	}
	mockClient := &mockDockerClient{}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{})

	scanners, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(scanners) != 2 {
		t.Errorf("expected 2 scanners, got %d", len(scanners))
	}
}

func TestService_Build(t *testing.T) {
	t.Run("builds from Dockerfile path", func(t *testing.T) {
		// Create temp scanners dir with Dockerfile
		scannersDir := t.TempDir()
		semgrepDir := filepath.Join(scannersDir, "semgrep")
		os.MkdirAll(semgrepDir, 0755)
		os.WriteFile(filepath.Join(semgrepDir, "Dockerfile"), []byte("FROM alpine"), 0644)

		mockSt := &mockStore{}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{ScannersDir: scannersDir})

		err := svc.Build(context.Background(), "semgrep")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(mockClient.imageBuilds) != 1 {
			t.Errorf("expected 1 image build, got %d", len(mockClient.imageBuilds))
		}
	})

	t.Run("empty scanner name returns error", func(t *testing.T) {
		mockSt := &mockStore{}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{})

		err := svc.Build(context.Background(), "")
		if err == nil || !strings.Contains(err.Error(), "scanner name is required") {
			t.Errorf("expected 'scanner name is required' error, got: %v", err)
		}
	})

	t.Run("missing Dockerfile returns error", func(t *testing.T) {
		scannersDir := t.TempDir()
		mockSt := &mockStore{}
		mockClient := &mockDockerClient{}
		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{ScannersDir: scannersDir})

		err := svc.Build(context.Background(), "nonexistent")
		if err == nil || !strings.Contains(err.Error(), "dockerfile not found") {
			t.Errorf("expected 'dockerfile not found' error, got: %v", err)
		}
	})
}

func TestService_Scan_Orchestration(t *testing.T) {
	t.Run("full scan orchestration: create run -> exec -> parse SARIF -> store findings", func(t *testing.T) {
		corpusDir := t.TempDir()
		outputDir := t.TempDir()

		mockSt := &mockStore{
			scanners: []store.Scanner{
				{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
			},
			projects: []store.CorpusProject{
				{ID: 1, Name: "test-project", LocalPath: corpusDir},
			},
		}

		sarifContent := `{
			"version": "2.1.0",
			"runs": [{
				"tool": {"driver": {"name": "test", "rules": []}},
				"results": [
					{
						"ruleId": "test-rule",
						"level": "warning",
						"message": {"text": "Test finding"},
						"locations": [{
							"physicalLocation": {
								"artifactLocation": {"uri": "test.py"},
								"region": {"startLine": 10, "endLine": 15}
							}
						}]
					}
				]
			}]
		}`
		mockClient := &mockDockerClient{
			exitCode: 0,
			onStart:  writeOutputOnStart("results.sarif", sarifContent),
		}

		runner, _ := NewDockerRunner(mockClient)
		svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

		run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{
			ExperimentID: 1,
			Iteration:    1,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify run was created
		if run.ID != 1 {
			t.Errorf("expected run ID 1, got %d", run.ID)
		}
		if run.ScannerID != 1 {
			t.Errorf("expected scanner ID 1, got %d", run.ScannerID)
		}
		if run.ProjectID != 1 {
			t.Errorf("expected project ID 1, got %d", run.ProjectID)
		}
		if run.Status != store.RunStatusCompleted {
			t.Errorf("expected status 'completed', got %q", run.Status)
		}

		// Verify findings were stored
		if len(mockSt.findings) != 1 {
			t.Errorf("expected 1 finding, got %d", len(mockSt.findings))
		}
		if len(mockSt.findings) > 0 {
			f := mockSt.findings[0]
			if f.FilePath != "test.py" {
				t.Errorf("expected file path 'test.py', got %q", f.FilePath)
			}
			if f.StartLine != 10 {
				t.Errorf("expected start line 10, got %d", f.StartLine)
			}
		}
	})
}

func TestService_Scan_UpdatesRunStatusToFailedOnContainerError(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	mockClient := &mockDockerClient{
		startErr: errors.New("container failed to start"),
	}

	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{})

	// Scan should return the run (not nil) even on container error
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run == nil {
		t.Fatal("expected run to be returned")
	}

	// Run status should be 'failed'
	if run.Status != store.RunStatusFailed {
		t.Errorf("expected status 'failed', got %q", run.Status)
	}

	// Error message should be captured
	if mockSt.lastUpdatedStatus != store.RunStatusFailed {
		t.Errorf("expected last updated status 'failed', got %q", mockSt.lastUpdatedStatus)
	}
	if !strings.Contains(mockSt.lastErrorMessage, "start container") {
		t.Errorf("expected error message about container, got %q", mockSt.lastErrorMessage)
	}
}

func TestService_Scan_NonExistentScanner(t *testing.T) {
	mockSt := &mockStore{
		scanners: []store.Scanner{},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: "/tmp"},
		},
	}

	mockClient := &mockDockerClient{}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{})

	_, err := svc.Scan(context.Background(), "nonexistent", "test-project", ScanOptions{})
	if err == nil {
		t.Fatal("expected error for non-existent scanner")
	}
	if !strings.Contains(err.Error(), "scanner not found") {
		t.Errorf("expected 'scanner not found' error, got: %v", err)
	}
}

func TestService_Scan_NonExistentProject(t *testing.T) {
	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
		},
		projects: []store.CorpusProject{},
	}

	mockClient := &mockDockerClient{}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{})

	_, err := svc.Scan(context.Background(), "semgrep", "nonexistent", ScanOptions{})
	if err == nil {
		t.Fatal("expected error for non-existent project")
	}
	if !strings.Contains(err.Error(), "project not found") {
		t.Errorf("expected 'project not found' error, got: %v", err)
	}
}

func TestService_Scan_NoSarifOutputMarksRunFailed(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	// Container exits successfully but produces no output
	mockClient := &mockDockerClient{
		exitCode: 0,
	}

	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Run should be marked as failed
	if run.Status != store.RunStatusFailed {
		t.Errorf("expected status 'failed', got %q", run.Status)
	}

	// Error message should mention no output
	if !strings.Contains(mockSt.lastErrorMessage, "no output") {
		t.Errorf("expected error about no output, got %q", mockSt.lastErrorMessage)
	}
}

func TestService_Scan_WithScannerConfig(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{
				ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest",
				ConfigJSON: sql.NullString{
					String: `{"output_format":"semgrep-json","entrypoint":["/usr/bin/semgrep"],"cmd":["scan","--json","--output=/output/results.json","/target"]}`,
					Valid:  true,
				},
			},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	semgrepJSON := `{
		"results": [{
			"check_id": "python.lang.security.audit.exec-detected",
			"path": "app.py",
			"start": {"line": 42, "col": 1, "offset": 100},
			"end": {"line": 42, "col": 20, "offset": 119},
			"extra": {
				"message": "Detected use of exec",
				"severity": "WARNING",
				"metadata": {"cwe": "CWE-95"},
				"lines": "exec(user_input)"
			}
		}],
		"errors": [],
		"version": "1.50.0"
	}`
	mockClient := &mockDockerClient{
		exitCode: 0,
		onStart:  writeOutputOnStart("results.json", semgrepJSON),
	}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{
		ExperimentID: 1,
		Iteration:    1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.Status != store.RunStatusCompleted {
		t.Errorf("expected status 'completed', got %q", run.Status)
	}

	// Verify findings were parsed from Semgrep JSON
	if len(mockSt.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(mockSt.findings))
	}
	f := mockSt.findings[0]
	if f.FilePath != "app.py" {
		t.Errorf("expected file path 'app.py', got %q", f.FilePath)
	}
	if f.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", f.StartLine)
	}

	// Verify entrypoint and cmd were passed to container
	config := mockClient.containerConfig
	if len(config.Entrypoint) != 1 || config.Entrypoint[0] != "/usr/bin/semgrep" {
		t.Errorf("expected entrypoint [/usr/bin/semgrep], got %v", config.Entrypoint)
	}
	if len(config.Cmd) != 4 || config.Cmd[0] != "scan" {
		t.Errorf("expected cmd [scan --json ...], got %v", config.Cmd)
	}
}

func TestService_Scan_WithConfigOverrides(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{
				ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest",
				ConfigJSON: sql.NullString{
					String: `{"output_format":"sarif"}`,
					Valid:  true,
				},
			},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	semgrepJSON := `{
		"results": [{
			"check_id": "rule1",
			"path": "main.py",
			"start": {"line": 10, "col": 1, "offset": 0},
			"end": {"line": 10, "col": 30, "offset": 29},
			"extra": {"message": "Finding", "severity": "ERROR", "metadata": {}, "lines": "code"}
		}],
		"errors": [],
		"version": "1.50.0"
	}`
	mockClient := &mockDockerClient{
		exitCode: 0,
		onStart:  writeOutputOnStart("results.json", semgrepJSON),
	}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{
		ConfigOverrides: &ScannerConfig{
			OutputFormat: "semgrep-json",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.Status != store.RunStatusCompleted {
		t.Errorf("expected status 'completed', got %q", run.Status)
	}
	if len(mockSt.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(mockSt.findings))
	}
	if mockSt.findings[0].FilePath != "main.py" {
		t.Errorf("expected file path 'main.py', got %q", mockSt.findings[0].FilePath)
	}
}

func TestService_Scan_CustomEnv(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{
				ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest",
				ConfigJSON: sql.NullString{
					String: `{"env":{"SEMGREP_RULES":"p/security-audit","EXTRA_FLAG":"true"}}`,
					Valid:  true,
				},
			},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	sarifContent := `{
		"version": "2.1.0",
		"runs": [{"tool": {"driver": {"name": "test", "rules": []}}, "results": []}]
	}`
	mockClient := &mockDockerClient{
		exitCode: 0,
		onStart:  writeOutputOnStart("results.sarif", sarifContent),
	}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

	svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{})

	// Check that scanner config env vars were merged into container env
	config := mockClient.containerConfig
	envMap := make(map[string]string)
	for _, env := range config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Standard env vars should be present
	if envMap["SCANNER_NAME"] != "semgrep" {
		t.Errorf("expected SCANNER_NAME='semgrep', got %q", envMap["SCANNER_NAME"])
	}
	// Config env vars should be merged in
	if envMap["SEMGREP_RULES"] != "p/security-audit" {
		t.Errorf("expected SEMGREP_RULES='p/security-audit', got %q", envMap["SEMGREP_RULES"])
	}
	if envMap["EXTRA_FLAG"] != "true" {
		t.Errorf("expected EXTRA_FLAG='true', got %q", envMap["EXTRA_FLAG"])
	}
}

func TestService_Scan_InvalidConfig(t *testing.T) {
	mockSt := &mockStore{
		scanners: []store.Scanner{
			{
				ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest",
				ConfigJSON: sql.NullString{String: `{invalid json`, Valid: true},
			},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: "/tmp"},
		},
	}

	mockClient := &mockDockerClient{}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{})

	_, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{})
	if err == nil {
		t.Fatal("expected error for invalid config JSON")
	}
	if !strings.Contains(err.Error(), "parse scanner config") {
		t.Errorf("expected 'parse scanner config' error, got: %v", err)
	}
}

func TestService_Scan_SemgrepJSON_EndToEnd(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{{
			ID: 1, Name: "semgrep", Version: "1.50.0",
			DockerImage: "semgrep:latest",
			ConfigJSON: sql.NullString{
				String: `{"output_format":"semgrep-json","output_file":"results.json"}`,
				Valid:  true,
			},
		}},
		projects: []store.CorpusProject{{
			ID: 1, Name: "test-project", LocalPath: corpusDir,
		}},
	}

	semgrepJSON := `{
		"results": [
			{
				"check_id": "python.flask.security.injection.sql-injection",
				"path": "app/db.py",
				"start": {"line": 42, "col": 5, "offset": 850},
				"end": {"line": 42, "col": 40, "offset": 885},
				"extra": {
					"message": "Detected SQL injection via string formatting",
					"severity": "ERROR",
					"metadata": {"cwe": ["CWE-89: SQL Injection"], "confidence": "HIGH", "category": "security"},
					"lines": "cursor.execute(query % user_input)"
				}
			},
			{
				"check_id": "python.lang.security.audit.exec-detected",
				"path": "app/utils.py",
				"start": {"line": 15, "col": 1, "offset": 200},
				"end": {"line": 15, "col": 25, "offset": 224},
				"extra": {
					"message": "Detected use of exec(). This can be dangerous if used with user input.",
					"severity": "WARNING",
					"metadata": {"cwe": "CWE-95: Eval Injection", "confidence": "MEDIUM", "category": "security"},
					"lines": "exec(user_input)"
				}
			}
		],
		"errors": [],
		"version": "1.50.0"
	}`
	mockClient := &mockDockerClient{
		exitCode: 0,
		onStart:  writeOutputOnStart("results.json", semgrepJSON),
	}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{
		ExperimentID: 1, Iteration: 1,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.Status != store.RunStatusCompleted {
		t.Fatalf("expected status 'completed', got %q (error: %s)", run.Status, mockSt.lastErrorMessage)
	}

	// Verify all findings were extracted
	if len(mockSt.findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(mockSt.findings))
	}

	// Verify first finding: SQL injection
	f1 := mockSt.findings[0]
	if f1.FilePath != "app/db.py" {
		t.Errorf("finding[0]: expected file path 'app/db.py', got %q", f1.FilePath)
	}
	if f1.StartLine != 42 {
		t.Errorf("finding[0]: expected start line 42, got %d", f1.StartLine)
	}
	if !f1.CWEID.Valid || f1.CWEID.String != "CWE-89" {
		t.Errorf("finding[0]: expected CWE 'CWE-89', got %v", f1.CWEID)
	}
	if !f1.Severity.Valid || f1.Severity.String != "high" {
		t.Errorf("finding[0]: expected severity 'high', got %v", f1.Severity)
	}
	if !f1.Message.Valid || !strings.Contains(f1.Message.String, "SQL injection") {
		t.Errorf("finding[0]: expected message about SQL injection, got %v", f1.Message)
	}
	if !f1.Snippet.Valid || !strings.Contains(f1.Snippet.String, "cursor.execute") {
		t.Errorf("finding[0]: expected snippet with 'cursor.execute', got %v", f1.Snippet)
	}
	if !f1.RuleID.Valid || f1.RuleID.String != "python.flask.security.injection.sql-injection" {
		t.Errorf("finding[0]: expected ruleID 'python.flask.security.injection.sql-injection', got %v", f1.RuleID)
	}

	// Verify second finding: exec detection
	f2 := mockSt.findings[1]
	if f2.FilePath != "app/utils.py" {
		t.Errorf("finding[1]: expected file path 'app/utils.py', got %q", f2.FilePath)
	}
	if f2.StartLine != 15 {
		t.Errorf("finding[1]: expected start line 15, got %d", f2.StartLine)
	}
	if !f2.CWEID.Valid || f2.CWEID.String != "CWE-95" {
		t.Errorf("finding[1]: expected CWE 'CWE-95', got %v", f2.CWEID)
	}
	if !f2.Severity.Valid || f2.Severity.String != "medium" {
		t.Errorf("finding[1]: expected severity 'medium', got %v", f2.Severity)
	}

	// Verify run metadata
	if run.ScannerID != 1 {
		t.Errorf("expected scanner ID 1, got %d", run.ScannerID)
	}
	if run.ProjectID != 1 {
		t.Errorf("expected project ID 1, got %d", run.ProjectID)
	}
	if run.Iteration != 1 {
		t.Errorf("expected iteration 1, got %d", run.Iteration)
	}

	// Verify container was configured correctly for Semgrep JSON output
	config := mockClient.containerConfig
	if config.Image != "semgrep:latest" {
		t.Errorf("expected image 'semgrep:latest', got %q", config.Image)
	}
}

func TestService_Scan_NoConfig_BackwardsCompatible(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	// Scanner with no config_json — should use SARIF parser (existing behavior)
	mockSt := &mockStore{
		scanners: []store.Scanner{{
			ID: 1, Name: "codeql", Version: "2.15.0",
			DockerImage: "codeql:latest",
			// No ConfigJSON set — zero value
		}},
		projects: []store.CorpusProject{{
			ID: 1, Name: "test-project", LocalPath: corpusDir,
		}},
	}

	sarifContent := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "codeql", "rules": [
				{"id": "js/sql-injection", "defaultConfiguration": {"level": "error"}}
			]}},
			"results": [
				{
					"ruleId": "js/sql-injection",
					"level": "error",
					"message": {"text": "SQL injection vulnerability"},
					"locations": [{
						"physicalLocation": {
							"artifactLocation": {"uri": "src/db.js"},
							"region": {"startLine": 88, "endLine": 90}
						}
					}]
				}
			]
		}]
	}`
	mockClient := &mockDockerClient{
		exitCode: 0,
		onStart:  writeOutputOnStart("results.sarif", sarifContent),
	}
	runner, _ := NewDockerRunner(mockClient)
	svc, _ := NewService(mockSt, runner, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "codeql", "test-project", ScanOptions{
		ExperimentID: 1, Iteration: 1,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run.Status != store.RunStatusCompleted {
		t.Fatalf("expected status 'completed', got %q (error: %s)", run.Status, mockSt.lastErrorMessage)
	}

	// Verify findings were parsed from SARIF
	if len(mockSt.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(mockSt.findings))
	}

	f := mockSt.findings[0]
	if f.FilePath != "src/db.js" {
		t.Errorf("expected file path 'src/db.js', got %q", f.FilePath)
	}
	if f.StartLine != 88 {
		t.Errorf("expected start line 88, got %d", f.StartLine)
	}
	if !f.RuleID.Valid || f.RuleID.String != "js/sql-injection" {
		t.Errorf("expected ruleID 'js/sql-injection', got %v", f.RuleID)
	}
	if !f.Severity.Valid || f.Severity.String != "high" {
		t.Errorf("expected severity 'high', got %v", f.Severity)
	}

	// Verify the default output file was used (results.sarif)
	// The container config should NOT have custom entrypoint or cmd
	config := mockClient.containerConfig
	if len(config.Entrypoint) != 0 {
		t.Errorf("expected no entrypoint override, got %v", config.Entrypoint)
	}
	if len(config.Cmd) != 0 {
		t.Errorf("expected no cmd override, got %v", config.Cmd)
	}
}

func TestService_Scan_Import_Success(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	// No Docker runner needed for import
	svc, _ := NewService(mockSt, nil, ServiceConfig{OutputDir: outputDir})

	// Create a SARIF file to import
	importDir := t.TempDir()
	importFile := filepath.Join(importDir, "external-results.sarif")
	sarifContent := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "semgrep", "rules": []}},
			"results": [
				{
					"ruleId": "imported-rule",
					"level": "warning",
					"message": {"text": "Imported finding"},
					"locations": [{
						"physicalLocation": {
							"artifactLocation": {"uri": "main.go"},
							"region": {"startLine": 5, "endLine": 5}
						}
					}]
				}
			]
		}]
	}`
	os.WriteFile(importFile, []byte(sarifContent), 0644)

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{
		ImportPath:   importFile,
		ExperimentID: 1,
		Iteration:    1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.Status != store.RunStatusCompleted {
		t.Errorf("expected status 'completed', got %q (error: %s)", run.Status, mockSt.lastErrorMessage)
	}

	// Verify findings were parsed from the imported SARIF
	if len(mockSt.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(mockSt.findings))
	}
	f := mockSt.findings[0]
	if f.FilePath != "main.go" {
		t.Errorf("expected file path 'main.go', got %q", f.FilePath)
	}
	if !f.RuleID.Valid || f.RuleID.String != "imported-rule" {
		t.Errorf("expected ruleID 'imported-rule', got %v", f.RuleID)
	}
}

func TestService_Scan_Import_FileNotFound(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	svc, _ := NewService(mockSt, nil, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{
		ImportPath: "/nonexistent/file.sarif",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Run should be marked as failed (not a hard error)
	if run.Status != store.RunStatusFailed {
		t.Errorf("expected status 'failed', got %q", run.Status)
	}
	if !strings.Contains(mockSt.lastErrorMessage, "import file not found") {
		t.Errorf("expected error about import file not found, got %q", mockSt.lastErrorMessage)
	}
}

func TestService_Scan_Import_FormatOverride(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	svc, _ := NewService(mockSt, nil, ServiceConfig{OutputDir: outputDir})

	// Create a Semgrep JSON file to import with format override
	importDir := t.TempDir()
	importFile := filepath.Join(importDir, "results.json")
	semgrepJSON := `{
		"results": [{
			"check_id": "python.lang.security.audit.exec-detected",
			"path": "app.py",
			"start": {"line": 42, "col": 1, "offset": 100},
			"end": {"line": 42, "col": 20, "offset": 119},
			"extra": {
				"message": "Detected use of exec",
				"severity": "WARNING",
				"metadata": {"cwe": "CWE-95"},
				"lines": "exec(user_input)"
			}
		}],
		"errors": [],
		"version": "1.50.0"
	}`
	os.WriteFile(importFile, []byte(semgrepJSON), 0644)

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{
		ImportPath:     importFile,
		FormatOverride: "semgrep-json",
		ExperimentID:   1,
		Iteration:      1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.Status != store.RunStatusCompleted {
		t.Errorf("expected status 'completed', got %q (error: %s)", run.Status, mockSt.lastErrorMessage)
	}

	// Verify findings were parsed as Semgrep JSON
	if len(mockSt.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(mockSt.findings))
	}
	if mockSt.findings[0].FilePath != "app.py" {
		t.Errorf("expected file path 'app.py', got %q", mockSt.findings[0].FilePath)
	}
}

func TestService_Scan_NilDockerRunner_WithoutImport_Fails(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	mockSt := &mockStore{
		scanners: []store.Scanner{
			{ID: 1, Name: "semgrep", Version: "1.0.0", DockerImage: "semgrep:latest"},
		},
		projects: []store.CorpusProject{
			{ID: 1, Name: "test-project", LocalPath: corpusDir},
		},
	}

	// No Docker runner and no import path = should fail
	svc, _ := NewService(mockSt, nil, ServiceConfig{OutputDir: outputDir})

	run, err := svc.Scan(context.Background(), "semgrep", "test-project", ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if run.Status != store.RunStatusFailed {
		t.Errorf("expected status 'failed', got %q", run.Status)
	}
	if !strings.Contains(mockSt.lastErrorMessage, "docker runner not configured") {
		t.Errorf("expected error about docker runner, got %q", mockSt.lastErrorMessage)
	}
}

func TestCanonicalizeFindingPath_ProjectRelativeFromAbsolute(t *testing.T) {
	projectRoot := filepath.Join(string(filepath.Separator), "tmp", "vulnerable-todoapp")

	got := canonicalizeFindingPath("/tmp/vulnerable-todoapp/routes/files.js", projectRoot)
	if got != "routes/files.js" {
		t.Errorf("canonicalizeFindingPath() = %q, want %q", got, "routes/files.js")
	}
}

func TestCanonicalizeFindingPath_DockerTargetPrefix(t *testing.T) {
	got := canonicalizeFindingPath("/target/routes/api.js", "")
	if got != "routes/api.js" {
		t.Errorf("canonicalizeFindingPath() = %q, want %q", got, "routes/api.js")
	}
}

func TestCanonicalizeFindingPath_FileURI(t *testing.T) {
	projectRoot := filepath.Join(string(filepath.Separator), "tmp", "vulnerable-todoapp")

	got := canonicalizeFindingPath("file:///tmp/vulnerable-todoapp/server.js", projectRoot)
	if got != "server.js" {
		t.Errorf("canonicalizeFindingPath() = %q, want %q", got, "server.js")
	}
}
