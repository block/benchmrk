package scanner

import (
	"encoding/json"
	"fmt"
)

// ScannerConfig holds structured execution parameters for a scanner.
// Stored as JSON in the scanner's config_json database field.
type ScannerConfig struct {
	// Cmd overrides the container's CMD. If empty, uses the image default (entrypoint.sh).
	Cmd []string `json:"cmd,omitempty"`

	// Entrypoint overrides the container's ENTRYPOINT. If empty, uses the image default.
	Entrypoint []string `json:"entrypoint,omitempty"`

	// Env contains additional environment variables passed to the container.
	// These are merged with the standard env vars (SCANNER_NAME, SCANNER_VERSION, TARGET_LANGUAGE).
	Env map[string]string `json:"env,omitempty"`

	// OutputFormat specifies the expected output format. Used by the normalisation
	// layer to select the appropriate converter.
	// Supported values: "sarif" (default), "semgrep-json".
	OutputFormat string `json:"output_format,omitempty"`

	// OutputFile specifies the output filename within /output/.
	// If empty, derived from OutputFormat: "sarif" → "results.sarif", others → "results.json".
	OutputFile string `json:"output_file,omitempty"`
}

// ParseScannerConfig parses a JSON string into a ScannerConfig.
// Returns a zero-value ScannerConfig if the input is empty.
func ParseScannerConfig(configJSON string) (ScannerConfig, error) {
	if configJSON == "" {
		return ScannerConfig{}, nil
	}
	var cfg ScannerConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return ScannerConfig{}, fmt.Errorf("parse scanner config: %w", err)
	}
	return cfg, nil
}

// Merge returns a new config with overrides applied on top of the base config.
// Non-zero override fields take precedence. Env maps are merged with override keys winning.
func (c ScannerConfig) Merge(overrides ScannerConfig) ScannerConfig {
	result := c
	if len(overrides.Cmd) > 0 {
		result.Cmd = overrides.Cmd
	}
	if len(overrides.Entrypoint) > 0 {
		result.Entrypoint = overrides.Entrypoint
	}
	if overrides.OutputFormat != "" {
		result.OutputFormat = overrides.OutputFormat
	}
	if overrides.OutputFile != "" {
		result.OutputFile = overrides.OutputFile
	}
	if len(overrides.Env) > 0 {
		if result.Env == nil {
			result.Env = make(map[string]string)
		}
		for k, v := range overrides.Env {
			result.Env[k] = v
		}
	}
	return result
}

// ResolvedOutputFile returns the expected output filename.
// If OutputFile is set explicitly, returns that.
// Otherwise derives from OutputFormat: "sarif" or "" → "results.sarif", anything else → "results.json".
func (c ScannerConfig) ResolvedOutputFile() string {
	if c.OutputFile != "" {
		return c.OutputFile
	}
	switch c.OutputFormat {
	case "sarif", "":
		return "results.sarif"
	default:
		return "results.json"
	}
}

// ResolvedOutputFormat returns the output format, defaulting to "sarif".
func (c ScannerConfig) ResolvedOutputFormat() string {
	if c.OutputFormat == "" {
		return "sarif"
	}
	return c.OutputFormat
}
