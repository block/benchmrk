package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// cappedWriter accepts writes up to limit bytes, then silently drops
// the rest. Used to bound scanner log capture — a runaway scanner
// shouldn't OOM the harness.
type cappedWriter struct {
	buf       strings.Builder
	limit     int
	truncated bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.truncated {
		return len(p), nil
	}
	room := w.limit - w.buf.Len()
	if room <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		w.buf.Write(p[:room])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *cappedWriter) Len() int { return w.buf.Len() }
func (w *cappedWriter) String() string {
	if w.truncated {
		return w.buf.String() + "\n... [output truncated]\n"
	}
	return w.buf.String()
}

// LocalRunOptions contains options for running a scanner as a local process.
type LocalRunOptions struct {
	ExecutablePath string
	Args           []string
	CorpusPath     string
	OutputDir      string
	TimeoutMinutes int
	EnvVars        map[string]string
	OutputFile     string // Expected output filename (default: "results.sarif")
}

// LocalRunner executes scanners as local processes instead of Docker containers.
type LocalRunner struct{}

// NewLocalRunner creates a new LocalRunner.
func NewLocalRunner() *LocalRunner {
	return &LocalRunner{}
}

// Run executes a scanner as a local process.
func (l *LocalRunner) Run(ctx context.Context, opts LocalRunOptions) (*RunResult, error) {
	if opts.ExecutablePath == "" {
		return nil, fmt.Errorf("executable path is required")
	}
	if opts.CorpusPath == "" {
		return nil, fmt.Errorf("corpus path is required")
	}
	if opts.OutputDir == "" {
		return nil, fmt.Errorf("output directory is required")
	}

	// Verify executable exists and is executable
	info, err := os.Stat(opts.ExecutablePath)
	if err != nil {
		return nil, fmt.Errorf("executable not found: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("executable path is a directory: %s", opts.ExecutablePath)
	}

	// Resolve absolute paths
	absCorpusPath, err := filepath.Abs(opts.CorpusPath)
	if err != nil {
		return nil, fmt.Errorf("resolve corpus path: %w", err)
	}
	absOutputDir, err := filepath.Abs(opts.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}

	// Verify corpus path exists
	if _, err := os.Stat(absCorpusPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("corpus path not found: %s", absCorpusPath)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(absOutputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	outputFile := opts.OutputFile
	if outputFile == "" {
		outputFile = "results.sarif"
	}

	result := &RunResult{
		OutputPath: filepath.Join(absOutputDir, outputFile),
	}

	// Create timeout context if specified
	var cancel context.CancelFunc
	if opts.TimeoutMinutes > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.TimeoutMinutes)*time.Minute)
		defer cancel()
	}

	// Build command
	cmd := exec.CommandContext(ctx, opts.ExecutablePath, opts.Args...)
	cmd.Dir = absCorpusPath

	// Minimal environment — scanner wrappers need PATH to find their
	// tool and HOME for config/cache dirs, but shouldn't inherit
	// AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, etc. Config-supplied vars
	// (opts.EnvVars) go last: last-wins lets a wrapper that genuinely
	// needs HTTPS_PROXY set it explicitly, but means the operator opted
	// in rather than leaking by default.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.Getenv("TMPDIR"),
		"LANG=" + os.Getenv("LANG"),
		"TARGET_DIR=" + absCorpusPath,
		"OUTPUT_DIR=" + absOutputDir,
	}
	for k, v := range opts.EnvVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Capture stdout and stderr, capped at maxLogBytes each.
	stdout := &cappedWriter{limit: maxLogBytes}
	stderr := &cappedWriter{limit: maxLogBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	startTime := time.Now()

	// Run the command
	runErr := cmd.Run()
	result.DurationMs = time.Since(startTime).Milliseconds()

	// Combine stdout and stderr as logs
	var logs strings.Builder
	if stdout.Len() > 0 {
		logs.WriteString(stdout.String())
	}
	if stderr.Len() > 0 {
		if logs.Len() > 0 {
			logs.WriteString("\n")
		}
		logs.WriteString(stderr.String())
	}
	result.Logs = logs.String()

	// Handle execution errors
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Errorf("process timed out after %d minutes", opts.TimeoutMinutes)
			return result, result.Error
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.ExitCode = int64(exitErr.ExitCode())
		} else {
			result.Error = fmt.Errorf("execute scanner: %w", runErr)
			return result, result.Error
		}
	}

	// Check if output file exists
	if _, err := os.Stat(result.OutputPath); os.IsNotExist(err) {
		result.OutputPath = ""
		if result.ExitCode == 0 {
			result.Error = fmt.Errorf("scanner completed but produced no output at %s", filepath.Join(absOutputDir, outputFile))
		}
	}

	// If exit code is non-zero and no other error, set the error
	if result.ExitCode != 0 && result.Error == nil {
		result.Error = fmt.Errorf("process exited with code %d", result.ExitCode)
	}

	return result, nil
}
