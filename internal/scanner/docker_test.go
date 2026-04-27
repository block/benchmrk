package scanner

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mockDockerClient implements DockerClient for testing.
type mockDockerClient struct {
	imageBuilds     []ImageBuildOptions
	containerConfig *ContainerConfig
	containerID     string
	exitCode        int64
	logs            string
	waitDuration    time.Duration
	onStart         func(config *ContainerConfig) // called during ContainerStart to simulate container output

	buildErr       error
	createErr      error
	startErr       error
	waitErr        error
	logsErr        error
	inspectErr     error
	removeErr      error
	stopErr        error
	waitCanceled   bool
	containerState *ContainerInspect
}

func (m *mockDockerClient) ImageBuild(ctx context.Context, buildContext io.Reader, options ImageBuildOptions) (io.ReadCloser, error) {
	m.imageBuilds = append(m.imageBuilds, options)
	if m.buildErr != nil {
		return nil, m.buildErr
	}
	return io.NopCloser(strings.NewReader("build output")), nil
}

func (m *mockDockerClient) ContainerCreate(ctx context.Context, config *ContainerConfig) (string, error) {
	m.containerConfig = config
	if m.createErr != nil {
		return "", m.createErr
	}
	if m.containerID == "" {
		m.containerID = "test-container-123"
	}
	return m.containerID, nil
}

func (m *mockDockerClient) ContainerStart(ctx context.Context, containerID string) error {
	if m.onStart != nil {
		m.onStart(m.containerConfig)
	}
	return m.startErr
}

func (m *mockDockerClient) ContainerWait(ctx context.Context, containerID string) (int64, error) {
	if m.waitDuration > 0 {
		select {
		case <-time.After(m.waitDuration):
		case <-ctx.Done():
			m.waitCanceled = true
			return 0, ctx.Err()
		}
	}
	return m.exitCode, m.waitErr
}

func (m *mockDockerClient) ContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	if m.logsErr != nil {
		return nil, m.logsErr
	}
	return io.NopCloser(strings.NewReader(m.logs)), nil
}

func (m *mockDockerClient) ContainerInspect(ctx context.Context, containerID string) (*ContainerInspect, error) {
	if m.inspectErr != nil {
		return nil, m.inspectErr
	}
	if m.containerState != nil {
		return m.containerState, nil
	}
	return &ContainerInspect{}, nil
}

func (m *mockDockerClient) ContainerRemove(ctx context.Context, containerID string, force bool) error {
	return m.removeErr
}

func (m *mockDockerClient) ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error {
	return m.stopErr
}

func TestNewDockerRunner(t *testing.T) {
	t.Run("success with valid client", func(t *testing.T) {
		client := &mockDockerClient{}
		runner, err := NewDockerRunner(client)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if runner == nil {
			t.Fatal("expected non-nil runner")
		}
	})

	t.Run("error with nil client", func(t *testing.T) {
		runner, err := NewDockerRunner(nil)
		if err == nil {
			t.Fatal("expected error for nil client")
		}
		if runner != nil {
			t.Fatal("expected nil runner")
		}
	})
}

func TestDockerRunner_Run_MountsAndEnvVars(t *testing.T) {
	// Create temp directories for corpus and output
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		exitCode: 0,
		logs:     "scan output",
	}

	runner, _ := NewDockerRunner(client)

	// Create a fake SARIF output file (simulating scanner output)
	sarifPath := filepath.Join(outputDir, "results.sarif")
	os.WriteFile(sarifPath, []byte(`{"version":"2.1.0"}`), 0644)

	opts := RunOptions{
		Image:      "test-scanner:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
		CPU:        2.0,
		MemoryMB:   1024,
		EnvVars: map[string]string{
			"SCANNER_NAME":    "test-scanner",
			"SCANNER_VERSION": "1.0.0",
			"TARGET_LANGUAGE": "python",
		},
	}

	result, err := runner.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify container config
	config := client.containerConfig
	if config == nil {
		t.Fatal("expected container config to be set")
	}

	// Check image
	if config.Image != "test-scanner:latest" {
		t.Errorf("expected image 'test-scanner:latest', got %q", config.Image)
	}

	// Check mounts
	if len(config.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(config.Mounts))
	}

	// Corpus mount should be read-only to /target
	corpusMount := config.Mounts[0]
	if corpusMount.Target != "/target" {
		t.Errorf("expected corpus mount target '/target', got %q", corpusMount.Target)
	}
	if !corpusMount.ReadOnly {
		t.Error("expected corpus mount to be read-only")
	}

	// Output mount should be writable to /output
	outputMount := config.Mounts[1]
	if outputMount.Target != "/output" {
		t.Errorf("expected output mount target '/output', got %q", outputMount.Target)
	}
	if outputMount.ReadOnly {
		t.Error("expected output mount to be writable")
	}

	// Network should be disabled — SAST has no business reaching out
	if config.NetworkMode != "none" {
		t.Errorf("expected NetworkMode 'none', got %q", config.NetworkMode)
	}

	// Check env vars
	envMap := make(map[string]string)
	for _, env := range config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	if envMap["SCANNER_NAME"] != "test-scanner" {
		t.Errorf("expected SCANNER_NAME='test-scanner', got %q", envMap["SCANNER_NAME"])
	}
	if envMap["SCANNER_VERSION"] != "1.0.0" {
		t.Errorf("expected SCANNER_VERSION='1.0.0', got %q", envMap["SCANNER_VERSION"])
	}
	if envMap["TARGET_LANGUAGE"] != "python" {
		t.Errorf("expected TARGET_LANGUAGE='python', got %q", envMap["TARGET_LANGUAGE"])
	}

	// Check resource limits
	if config.CPUQuota != 200000 {
		t.Errorf("expected CPU quota 200000, got %d", config.CPUQuota)
	}
	if config.MemoryMB != 1024 {
		t.Errorf("expected memory 1024MB, got %d", config.MemoryMB)
	}

	// Check result
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if result.OutputPath != sarifPath {
		t.Errorf("expected output path %q, got %q", sarifPath, result.OutputPath)
	}
}

func TestDockerRunner_Run_CapturesExitCodeAndDuration(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		exitCode:     42,
		waitDuration: 100 * time.Millisecond,
	}

	runner, _ := NewDockerRunner(client)

	opts := RunOptions{
		Image:      "test-scanner:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
	}

	result, _ := runner.Run(context.Background(), opts)

	// Check exit code is captured
	if result.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", result.ExitCode)
	}

	// Check duration is captured (should be at least 100ms)
	if result.DurationMs < 100 {
		t.Errorf("expected duration >= 100ms, got %dms", result.DurationMs)
	}
}

func TestDockerRunner_Run_EnforcesTimeout(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		waitDuration: 10 * time.Second, // Long wait to trigger timeout
	}

	runner, _ := NewDockerRunner(client)

	opts := RunOptions{
		Image:          "test-scanner:latest",
		CorpusPath:     corpusDir,
		OutputDir:      outputDir,
		TimeoutMinutes: 0, // Use context timeout instead for faster test
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, err := runner.Run(ctx, opts)

	// Should have an error about timeout
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if result.Error == nil {
		t.Fatal("expected result.Error to be set")
	}
	if !client.waitCanceled {
		t.Error("expected wait to be canceled")
	}
}

func TestDockerRunner_Run_HandlesContainerStartupFailure(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		startErr: errors.New("container startup failed: image not found"),
	}

	runner, _ := NewDockerRunner(client)

	opts := RunOptions{
		Image:      "nonexistent:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
	}

	result, err := runner.Run(context.Background(), opts)

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "start container") {
		t.Errorf("expected start container error, got: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected result.Error to be set")
	}
}

func TestDockerRunner_Run_HandlesContainerCreateFailure(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		createErr: errors.New("cannot create container"),
	}

	runner, _ := NewDockerRunner(client)

	opts := RunOptions{
		Image:      "test:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
	}

	result, err := runner.Run(context.Background(), opts)

	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "create container") {
		t.Errorf("expected create container error, got: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected result.Error to be set")
	}
}

func TestDockerRunner_Run_MissingImage(t *testing.T) {
	_, err := (&DockerRunner{}).Run(context.Background(), RunOptions{
		CorpusPath: "/tmp",
		OutputDir:  "/tmp",
	})
	if err == nil || !strings.Contains(err.Error(), "image is required") {
		t.Errorf("expected 'image is required' error, got: %v", err)
	}
}

func TestDockerRunner_Run_MissingCorpusPath(t *testing.T) {
	client := &mockDockerClient{}
	runner, _ := NewDockerRunner(client)

	_, err := runner.Run(context.Background(), RunOptions{
		Image:     "test:latest",
		OutputDir: "/tmp",
	})
	if err == nil || !strings.Contains(err.Error(), "corpus path is required") {
		t.Errorf("expected 'corpus path is required' error, got: %v", err)
	}
}

func TestDockerRunner_Run_NonexistentCorpusPath(t *testing.T) {
	client := &mockDockerClient{}
	runner, _ := NewDockerRunner(client)

	_, err := runner.Run(context.Background(), RunOptions{
		Image:      "test:latest",
		CorpusPath: "/nonexistent/path",
		OutputDir:  "/tmp",
	})
	if err == nil || !strings.Contains(err.Error(), "corpus path not found") {
		t.Errorf("expected 'corpus path not found' error, got: %v", err)
	}
}

func TestDockerRunner_Run_NoSarifOutput(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		exitCode: 0,
	}

	runner, _ := NewDockerRunner(client)

	opts := RunOptions{
		Image:      "test-scanner:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
	}

	result, _ := runner.Run(context.Background(), opts)

	// Should have empty output path
	if result.OutputPath != "" {
		t.Errorf("expected empty output path, got %q", result.OutputPath)
	}

	// Should have an error about no output
	if result.Error == nil {
		t.Fatal("expected error about no output")
	}
	if !strings.Contains(result.Error.Error(), "no output") {
		t.Errorf("expected 'no output' error, got: %v", result.Error)
	}
}

func TestDockerRunner_Run_CustomOutputFile(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		exitCode: 0,
	}

	runner, _ := NewDockerRunner(client)

	// Create the custom output file
	customFile := filepath.Join(outputDir, "results.json")
	os.WriteFile(customFile, []byte(`{"results":[]}`), 0644)

	opts := RunOptions{
		Image:      "test-scanner:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
		OutputFile: "results.json",
	}

	result, err := runner.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.OutputPath != customFile {
		t.Errorf("expected output path %q, got %q", customFile, result.OutputPath)
	}
}

func TestDockerRunner_Run_DefaultOutputFile(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		exitCode: 0,
	}

	runner, _ := NewDockerRunner(client)

	// Create the default output file
	defaultFile := filepath.Join(outputDir, "results.sarif")
	os.WriteFile(defaultFile, []byte(`{"version":"2.1.0"}`), 0644)

	opts := RunOptions{
		Image:      "test-scanner:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
		// No OutputFile set — should default to "results.sarif"
	}

	result, err := runner.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.OutputPath != defaultFile {
		t.Errorf("expected output path %q, got %q", defaultFile, result.OutputPath)
	}
}

func TestDockerRunner_Run_CustomCmdAndEntrypoint(t *testing.T) {
	corpusDir := t.TempDir()
	outputDir := t.TempDir()

	client := &mockDockerClient{
		exitCode: 0,
	}

	runner, _ := NewDockerRunner(client)

	opts := RunOptions{
		Image:      "test-scanner:latest",
		CorpusPath: corpusDir,
		OutputDir:  outputDir,
		Cmd:        []string{"--format", "json"},
		Entrypoint: []string{"/usr/bin/semgrep", "scan"},
	}

	runner.Run(context.Background(), opts)

	config := client.containerConfig
	if config == nil {
		t.Fatal("expected container config to be set")
	}

	// Verify entrypoint was passed through
	if len(config.Entrypoint) != 2 {
		t.Fatalf("expected 2 entrypoint parts, got %d", len(config.Entrypoint))
	}
	if config.Entrypoint[0] != "/usr/bin/semgrep" {
		t.Errorf("expected entrypoint[0] '/usr/bin/semgrep', got %q", config.Entrypoint[0])
	}
	if config.Entrypoint[1] != "scan" {
		t.Errorf("expected entrypoint[1] 'scan', got %q", config.Entrypoint[1])
	}

	// Verify cmd was passed through
	if len(config.Cmd) != 2 {
		t.Fatalf("expected 2 cmd parts, got %d", len(config.Cmd))
	}
	if config.Cmd[0] != "--format" {
		t.Errorf("expected cmd[0] '--format', got %q", config.Cmd[0])
	}
	if config.Cmd[1] != "json" {
		t.Errorf("expected cmd[1] 'json', got %q", config.Cmd[1])
	}
}

func TestDockerRunner_BuildImage(t *testing.T) {
	// Create temp dir with Dockerfile
	scannerDir := t.TempDir()
	dockerfilePath := filepath.Join(scannerDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine:latest"), 0644); err != nil {
		t.Fatalf("failed to create Dockerfile: %v", err)
	}

	client := &mockDockerClient{}
	runner, _ := NewDockerRunner(client)

	tag, err := runner.BuildImage(context.Background(), "test-scanner", dockerfilePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedTag := "benchmrk-scanner-test-scanner:latest"
	if tag != expectedTag {
		t.Errorf("expected tag %q, got %q", expectedTag, tag)
	}

	if len(client.imageBuilds) != 1 {
		t.Fatalf("expected 1 image build, got %d", len(client.imageBuilds))
	}

	if client.imageBuilds[0].Tags[0] != expectedTag {
		t.Errorf("expected build tag %q, got %q", expectedTag, client.imageBuilds[0].Tags[0])
	}
}

func TestDockerRunner_BuildImage_DockerfileNotFound(t *testing.T) {
	client := &mockDockerClient{}
	runner, _ := NewDockerRunner(client)

	_, err := runner.BuildImage(context.Background(), "test-scanner", "/nonexistent/Dockerfile")
	if err == nil || !strings.Contains(err.Error(), "dockerfile not found") {
		t.Errorf("expected 'dockerfile not found' error, got: %v", err)
	}
}

func TestDockerRunner_BuildImage_EmptyScannerName(t *testing.T) {
	client := &mockDockerClient{}
	runner, _ := NewDockerRunner(client)

	_, err := runner.BuildImage(context.Background(), "", "/tmp/Dockerfile")
	if err == nil || !strings.Contains(err.Error(), "scanner name is required") {
		t.Errorf("expected 'scanner name is required' error, got: %v", err)
	}
}

func TestDockerRunner_BuildImage_BuildError(t *testing.T) {
	scannerDir := t.TempDir()
	dockerfilePath := filepath.Join(scannerDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine:latest"), 0644); err != nil {
		t.Fatalf("failed to create Dockerfile: %v", err)
	}

	client := &mockDockerClient{
		buildErr: errors.New("build failed"),
	}
	runner, _ := NewDockerRunner(client)

	_, err := runner.BuildImage(context.Background(), "test-scanner", dockerfilePath)
	if err == nil || !strings.Contains(err.Error(), "build image") {
		t.Errorf("expected 'build image' error, got: %v", err)
	}
}
