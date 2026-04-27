package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// RealDockerClient implements the DockerClient interface using the Docker CLI.
// This is a simplified implementation that shells out to the Docker binary.
type RealDockerClient struct{}

// NewRealDockerClient creates a new RealDockerClient after verifying Docker is available.
func NewRealDockerClient() (*RealDockerClient, error) {
	// Check if docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found in PATH: %w", err)
	}

	// Verify docker daemon is running
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker daemon not running: %w", err)
	}

	return &RealDockerClient{}, nil
}

// ImageBuild builds a Docker image from the provided context.
func (c *RealDockerClient) ImageBuild(ctx context.Context, buildContext io.Reader, options ImageBuildOptions) (io.ReadCloser, error) {
	args := []string{"build"}

	for _, tag := range options.Tags {
		args = append(args, "-t", tag)
	}

	if options.Dockerfile != "" {
		args = append(args, "-f", options.Dockerfile)
	}

	args = append(args, "-")

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = buildContext

	// CombinedOutput captures both stdout and stderr, which is necessary
	// because BuildKit sends build output (including errors) to stderr.
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("build failed: %s: %w", string(output), err)
	}

	return io.NopCloser(bytes.NewReader(output)), nil
}

// ContainerCreate creates a new container.
func (c *RealDockerClient) ContainerCreate(ctx context.Context, config *ContainerConfig) (string, error) {
	args := []string{"create"}

	for _, env := range config.Env {
		args = append(args, "-e", env)
	}

	for _, mount := range config.Mounts {
		mountOpt := fmt.Sprintf("%s:%s", mount.Source, mount.Target)
		if mount.ReadOnly {
			mountOpt += ":ro"
		}
		args = append(args, "-v", mountOpt)
	}

	if config.WorkingDir != "" {
		args = append(args, "-w", config.WorkingDir)
	}

	if config.NetworkMode != "" {
		args = append(args, "--network", config.NetworkMode)
	}

	if config.MemoryMB > 0 {
		args = append(args, "-m", fmt.Sprintf("%dm", config.MemoryMB))
	}

	if config.CPUQuota > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(config.CPUQuota)/100000))
	}

	if len(config.Entrypoint) > 0 {
		args = append(args, "--entrypoint", config.Entrypoint[0])
	}

	args = append(args, config.Image)

	// If entrypoint was overridden with multiple parts, remaining parts go before cmd
	if len(config.Entrypoint) > 1 {
		args = append(args, config.Entrypoint[1:]...)
	}
	args = append(args, config.Cmd...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("create container: %s: %w", stderr.String(), err)
	}

	// Container ID is the output (trimmed)
	containerID := string(output)
	if len(containerID) > 0 && containerID[len(containerID)-1] == '\n' {
		containerID = containerID[:len(containerID)-1]
	}

	return containerID, nil
}

// ContainerStart starts a container.
func (c *RealDockerClient) ContainerStart(ctx context.Context, containerID string) error {
	cmd := exec.CommandContext(ctx, "docker", "start", containerID)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	return nil
}

// ContainerWait waits for a container to stop and returns its exit code.
func (c *RealDockerClient) ContainerWait(ctx context.Context, containerID string) (int64, error) {
	cmd := exec.CommandContext(ctx, "docker", "wait", containerID)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("wait for container: %w", err)
	}

	var exitCode int64
	if _, err := fmt.Sscanf(string(output), "%d", &exitCode); err != nil {
		return 0, fmt.Errorf("parse exit code: %w", err)
	}

	return exitCode, nil
}

// ContainerLogs returns the logs from a container.
func (c *RealDockerClient) ContainerLogs(ctx context.Context, containerID string) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, "docker", "logs", containerID)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("get stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start logs: %w", err)
	}

	// Wait in goroutine to clean up
	go func() {
		cmd.Wait()
	}()

	return stdout, nil
}

// ContainerInspect returns information about a container.
func (c *RealDockerClient) ContainerInspect(ctx context.Context, containerID string) (*ContainerInspect, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.ExitCode}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}

	var exitCode int64
	if _, err := fmt.Sscanf(string(output), "%d", &exitCode); err != nil {
		return nil, fmt.Errorf("parse exit code: %w", err)
	}

	result := &ContainerInspect{}
	result.State.ExitCode = exitCode
	return result, nil
}

// ContainerRemove removes a container.
func (c *RealDockerClient) ContainerRemove(ctx context.Context, containerID string, force bool) error {
	args := []string{"rm"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, containerID)

	cmd := exec.CommandContext(ctx, "docker", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("remove container: %w", err)
	}
	return nil
}

// ContainerStop stops a container.
func (c *RealDockerClient) ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error {
	args := []string{"stop"}
	if timeout != nil {
		args = append(args, "-t", fmt.Sprintf("%d", int(timeout.Seconds())))
	}
	args = append(args, containerID)

	cmd := exec.CommandContext(ctx, "docker", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("stop container: %w", err)
	}
	return nil
}
