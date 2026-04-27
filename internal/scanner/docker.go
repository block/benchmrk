// Package scanner provides Docker-based scanner orchestration for SAST tools.
package scanner

import (
	"archive/tar"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DockerClient defines the interface for Docker operations.
// This abstraction allows for easy testing with mocks.
type DockerClient interface {
	ImageBuild(ctx context.Context, buildContext io.Reader, options ImageBuildOptions) (io.ReadCloser, error)
	ContainerCreate(ctx context.Context, config *ContainerConfig) (string, error)
	ContainerStart(ctx context.Context, containerID string) error
	ContainerWait(ctx context.Context, containerID string) (int64, error)
	ContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error)
	ContainerInspect(ctx context.Context, containerID string) (*ContainerInspect, error)
	ContainerRemove(ctx context.Context, containerID string, force bool) error
	ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error
}

// ImageBuildOptions contains options for building a Docker image.
type ImageBuildOptions struct {
	Tags       []string
	Dockerfile string
}

// ContainerConfig contains configuration for creating a container.
type ContainerConfig struct {
	Image       string
	Cmd         []string
	Entrypoint  []string
	Env         []string
	Mounts      []Mount
	CPUQuota    int64
	MemoryMB    int64
	WorkingDir  string
	NetworkMode string // "none" by default — SAST doesn't need network
}

// maxLogBytes caps captured scanner stdout/stderr. A chatty scanner on
// a large corpus can emit hundreds of MB; we only need enough to
// diagnose failures.
const maxLogBytes = 10 * 1024 * 1024

// Mount represents a bind mount configuration.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// ContainerInspect contains container state information.
type ContainerInspect struct {
	State struct {
		ExitCode int64
		Running  bool
		Status   string
	}
}

// RunOptions contains options for running a scanner container.
type RunOptions struct {
	Image          string
	CorpusPath     string
	OutputDir      string
	CPU            float64
	MemoryMB       int64
	TimeoutMinutes int
	EnvVars        map[string]string
	Cmd            []string // Override container CMD
	Entrypoint     []string // Override container ENTRYPOINT
	OutputFile     string   // Expected output filename (default: "results.sarif")
}

// RunResult contains the results of a scanner run.
type RunResult struct {
	ExitCode        int64
	DurationMs      int64
	MemoryPeakBytes int64
	OutputPath      string // Path to scanner output file (renamed from SarifPath)
	Logs            string
	Error           error
}

// DockerRunner orchestrates Docker containers for running SAST scanners.
type DockerRunner struct {
	client    DockerClient
	logWriter io.Writer // Optional writer for build/run output logging
}

// NewDockerRunner creates a new DockerRunner with the given Docker client.
func NewDockerRunner(client DockerClient) (*DockerRunner, error) {
	if client == nil {
		return nil, fmt.Errorf("docker client is required")
	}
	return &DockerRunner{client: client}, nil
}

// SetLogWriter sets an optional writer for capturing build and execution output.
// Useful for verbose logging during debugging.
func (d *DockerRunner) SetLogWriter(w io.Writer) {
	d.logWriter = w
}

// BuildImage builds a Docker image from the specified Dockerfile.
func (d *DockerRunner) BuildImage(ctx context.Context, scannerName, dockerfilePath string) (string, error) {
	if scannerName == "" {
		return "", fmt.Errorf("scanner name is required")
	}
	if dockerfilePath == "" {
		return "", fmt.Errorf("dockerfile path is required")
	}

	// Verify dockerfile exists
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		return "", fmt.Errorf("dockerfile not found: %s", dockerfilePath)
	}

	// Create tar archive of the build context (directory containing Dockerfile)
	buildContextDir := filepath.Dir(dockerfilePath)
	tarReader, err := createTarArchive(buildContextDir)
	if err != nil {
		return "", fmt.Errorf("create build context: %w", err)
	}
	defer tarReader.Close()

	tag := fmt.Sprintf("benchmrk-scanner-%s:latest", scannerName)
	options := ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: filepath.Base(dockerfilePath),
	}

	response, err := d.client.ImageBuild(ctx, tarReader, options)
	if err != nil {
		return "", fmt.Errorf("build image: %w", err)
	}
	defer response.Close()

	// Capture build output - either to the configured writer or to a buffer for error reporting
	var buildOutput strings.Builder
	var outputWriter io.Writer = &buildOutput
	if d.logWriter != nil {
		outputWriter = io.MultiWriter(d.logWriter, &buildOutput)
	}

	if _, err := io.Copy(outputWriter, response); err != nil {
		return "", fmt.Errorf("read build output: %w", err)
	}

	// Check for build errors in output (Docker build returns errors in the stream)
	output := buildOutput.String()
	if strings.Contains(output, "error:") || strings.Contains(output, "ERROR:") {
		// Extract last portion of output for error context
		lines := strings.Split(output, "\n")
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		return "", fmt.Errorf("build failed:\n%s", strings.Join(lines, "\n"))
	}

	return tag, nil
}

// Run executes a scanner container with the specified options.
func (d *DockerRunner) Run(ctx context.Context, opts RunOptions) (*RunResult, error) {
	if opts.Image == "" {
		return nil, fmt.Errorf("image is required")
	}
	if opts.CorpusPath == "" {
		return nil, fmt.Errorf("corpus path is required")
	}
	if opts.OutputDir == "" {
		return nil, fmt.Errorf("output directory is required")
	}

	// Docker requires absolute paths for bind mounts
	absOutputDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	opts.OutputDir = absOutputDir

	// Verify corpus path exists
	if _, err := os.Stat(opts.CorpusPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("corpus path not found: %s", opts.CorpusPath)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(opts.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	outputFile := opts.OutputFile
	if outputFile == "" {
		outputFile = "results.sarif"
	}
	result := &RunResult{
		OutputPath: filepath.Join(opts.OutputDir, outputFile),
	}

	// Build environment variables
	env := make([]string, 0, len(opts.EnvVars))
	for k, v := range opts.EnvVars {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	// Configure container. NetworkMode=none: SAST scanners analyse a
	// read-only mount and write to a local directory — they have no
	// business reaching the network, and a compromised scanner image
	// shouldn't be able to exfiltrate source.
	config := &ContainerConfig{
		Image:       opts.Image,
		Cmd:         opts.Cmd,
		Entrypoint:  opts.Entrypoint,
		Env:         env,
		NetworkMode: "none",
		Mounts: []Mount{
			{Source: opts.CorpusPath, Target: "/target", ReadOnly: true},
			{Source: opts.OutputDir, Target: "/output", ReadOnly: false},
		},
		WorkingDir: "/target",
	}

	// Set resource limits
	if opts.CPU > 0 {
		config.CPUQuota = int64(opts.CPU * 100000) // CPU quota in microseconds per 100ms
	}
	if opts.MemoryMB > 0 {
		config.MemoryMB = opts.MemoryMB
	}

	// Create timeout context if specified
	var cancel context.CancelFunc
	if opts.TimeoutMinutes > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.TimeoutMinutes)*time.Minute)
		defer cancel()
	}

	startTime := time.Now()

	// Create container
	containerID, err := d.client.ContainerCreate(ctx, config)
	if err != nil {
		result.Error = fmt.Errorf("create container: %w", err)
		return result, result.Error
	}

	// Always clean up container
	defer func() {
		d.client.ContainerRemove(context.Background(), containerID, true)
	}()

	// Start container
	if err := d.client.ContainerStart(ctx, containerID); err != nil {
		result.Error = fmt.Errorf("start container: %w", err)
		return result, result.Error
	}

	// Wait for container to complete
	exitCode, err := d.client.ContainerWait(ctx, containerID)
	result.DurationMs = time.Since(startTime).Milliseconds()

	if err != nil {
		// Check if it was a timeout
		if ctx.Err() == context.DeadlineExceeded {
			// Stop the container on timeout
			timeout := 5 * time.Second
			d.client.ContainerStop(context.Background(), containerID, &timeout)
			result.Error = fmt.Errorf("container timed out after %d minutes", opts.TimeoutMinutes)
			return result, result.Error
		}
		result.Error = fmt.Errorf("wait for container: %w", err)
		return result, result.Error
	}

	result.ExitCode = exitCode

	// Capture container logs, capped at maxLogBytes.
	logReader, err := d.client.ContainerLogs(ctx, containerID)
	if err == nil && logReader != nil {
		defer logReader.Close()
		var logs strings.Builder
		scanner := bufio.NewScanner(logReader)
		for scanner.Scan() {
			line := scanner.Text()
			if logs.Len()+len(line)+1 > maxLogBytes {
				logs.WriteString("\n... [log output truncated]\n")
				break
			}
			logs.WriteString(line)
			logs.WriteString("\n")
		}
		result.Logs = logs.String()
	}

	// Get memory stats from container inspect
	inspect, err := d.client.ContainerInspect(ctx, containerID)
	if err == nil && inspect != nil {
		// Memory peak is typically captured during container lifecycle
		// For now, we'll leave this as 0 as accurate memory tracking
		// requires reading from cgroup stats during execution
		result.MemoryPeakBytes = 0
	}

	// Check if output file exists
	if _, err := os.Stat(result.OutputPath); os.IsNotExist(err) {
		result.OutputPath = ""
		if result.ExitCode == 0 {
			result.Error = fmt.Errorf("scanner completed but produced no output")
		}
	}

	// If exit code is non-zero and no other error, set the error
	if result.ExitCode != 0 && result.Error == nil {
		result.Error = fmt.Errorf("container exited with code %d", result.ExitCode)
	}

	return result, nil
}

// tarReader is a wrapper to allow closing the pipe
type tarReader struct {
	io.Reader
	cleanup func()
}

func (t *tarReader) Close() error {
	if t.cleanup != nil {
		t.cleanup()
	}
	return nil
}

// createTarArchive creates a tar archive of the given directory for Docker build context.
func createTarArchive(dir string) (io.ReadCloser, error) {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		if err := tarDirectory(dir, pw); err != nil {
			pw.CloseWithError(err)
		}
	}()

	return &tarReader{Reader: pr, cleanup: func() { pr.Close() }}, nil
}

// tarDirectory writes the contents of dir to w as a tar archive.
func tarDirectory(dir string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get the relative path for the tar entry
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("get relative path: %w", err)
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Create tar header from file info
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("create tar header: %w", err)
		}

		// Use relative path as the name in the archive
		header.Name = relPath

		// Handle symlinks
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("read symlink: %w", err)
			}
			header.Linkname = linkTarget
		}

		// Write header
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header: %w", err)
		}

		// If it's a regular file, write its contents
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("open file: %w", err)
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return fmt.Errorf("copy file to tar: %w", err)
			}
		}

		return nil
	})
}
