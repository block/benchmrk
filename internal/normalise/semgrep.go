package normalise

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/block/benchmrk/internal/sarif"
)

// SemgrepOutput represents the top-level structure of Semgrep's native JSON output.
type SemgrepOutput struct {
	Results []SemgrepResult `json:"results"`
	Errors  []SemgrepError  `json:"errors"`
	Version string          `json:"version"`
}

// SemgrepResult represents a single finding in Semgrep's native JSON.
type SemgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   SemgrepPos   `json:"start"`
	End     SemgrepPos   `json:"end"`
	Extra   SemgrepExtra `json:"extra"`
}

// SemgrepPos represents a position in a file.
type SemgrepPos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// SemgrepExtra contains additional finding metadata.
type SemgrepExtra struct {
	Message  string          `json:"message"`
	Severity string          `json:"severity"`
	Metadata SemgrepMetadata `json:"metadata"`
	Lines    string          `json:"lines"`
}

// SemgrepMetadata contains rule metadata from Semgrep.
type SemgrepMetadata struct {
	CWE        interface{} `json:"cwe"` // string or []string
	Confidence string      `json:"confidence"`
	Category   string      `json:"category"`
}

// SemgrepError represents an error entry in Semgrep output.
type SemgrepError struct {
	Message string `json:"message"`
	Level   string `json:"level"`
}

// SemgrepConverter implements Converter for Semgrep's native JSON format.
type SemgrepConverter struct{}

func (s *SemgrepConverter) Convert(r io.Reader) (*sarif.SarifReport, error) {
	var output SemgrepOutput
	if err := json.NewDecoder(r).Decode(&output); err != nil {
		return nil, fmt.Errorf("parse semgrep JSON: %w", err)
	}

	// Build SARIF results from Semgrep results
	results := make([]sarif.Result, len(output.Results))
	for i, sr := range output.Results {
		startLine := sr.Start.Line
		endLine := sr.End.Line

		results[i] = sarif.Result{
			RuleID:  sr.CheckID,
			Level:   semgrepSeverityToSARIF(sr.Extra.Severity),
			Message: sarif.Message{Text: sr.Extra.Message},
			Locations: []sarif.Location{{
				PhysicalLocation: &sarif.PhysicalLocation{
					ArtifactLocation: &sarif.ArtifactLocation{URI: sr.Path},
					Region: &sarif.Region{
						StartLine: &startLine,
						EndLine:   &endLine,
						Snippet:   &sarif.ArtifactContent{Text: sr.Extra.Lines},
					},
				},
			}},
		}
	}

	// Build rules from unique check_ids
	rulesMap := make(map[string]sarif.ReportingDescriptor)
	for _, sr := range output.Results {
		if _, exists := rulesMap[sr.CheckID]; exists {
			continue
		}
		rule := sarif.ReportingDescriptor{
			ID: sr.CheckID,
			DefaultConfig: &sarif.ReportingConfig{
				Level: semgrepSeverityToSARIF(sr.Extra.Severity),
			},
		}
		if cwe := extractSemgrepCWE(sr.Extra.Metadata.CWE); cwe != "" {
			rule.Properties = &sarif.PropertyBag{CWE: cwe}
		}
		rulesMap[sr.CheckID] = rule
	}
	rules := make([]sarif.ReportingDescriptor, 0, len(rulesMap))
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	report := &sarif.SarifReport{
		Version: "2.1.0",
		Runs: []sarif.Run{{
			Tool: sarif.Tool{
				Driver: sarif.ToolComponent{
					Name:    "Semgrep",
					Version: output.Version,
					Rules:   rules,
				},
			},
			Results: results,
		}},
	}

	return report, nil
}

// semgrepSeverityToSARIF maps Semgrep severity strings to SARIF levels.
func semgrepSeverityToSARIF(severity string) string {
	switch strings.ToUpper(severity) {
	case "ERROR":
		return "error"
	case "WARNING":
		return "warning"
	case "INFO":
		return "note"
	default:
		return "warning"
	}
}

// extractSemgrepCWE extracts the first CWE ID from Semgrep metadata.
// Semgrep CWE field can be a string or []string.
func extractSemgrepCWE(cwe interface{}) string {
	switch v := cwe.(type) {
	case string:
		return extractCWEID(v)
	case []interface{}:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return extractCWEID(s)
			}
		}
	}
	return ""
}

// extractCWEID extracts just the CWE-NNN part from strings like
// "CWE-89: Improper Neutralization of Special Elements..."
func extractCWEID(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, ":"); idx > 0 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToUpper(s), "CWE") {
		return s
	}
	return ""
}
