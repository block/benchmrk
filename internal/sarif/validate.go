package sarif

import (
	"fmt"
)

const SupportedVersion = "2.1.0"

// Validate checks that the SARIF report is valid and meets minimum requirements.
// Returns a slice of validation errors (empty slice means valid).
func Validate(report *SarifReport) []error {
	var errs []error

	if report == nil {
		return []error{fmt.Errorf("report is nil")}
	}

	// Check SARIF version
	if report.Version != SupportedVersion {
		errs = append(errs, fmt.Errorf("unsupported SARIF version %q, expected %q", report.Version, SupportedVersion))
	}

	// Check for at least one run
	if len(report.Runs) == 0 {
		errs = append(errs, fmt.Errorf("SARIF report must contain at least one run"))
	}

	// Validate each run
	for i, run := range report.Runs {
		if run.Tool.Driver.Name == "" {
			errs = append(errs, fmt.Errorf("run[%d]: tool driver name is required", i))
		}
	}

	return errs
}
