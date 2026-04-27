package sarif

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Parse reads a SARIF 2.1.0 document from an io.Reader using streaming JSON parsing.
func Parse(r io.Reader) (*SarifReport, error) {
	decoder := json.NewDecoder(r)
	var report SarifReport
	if err := decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF: %w", err)
	}
	return &report, nil
}

// ExtractFindings converts SARIF results into flat Finding structs.
func ExtractFindings(report *SarifReport) ([]Finding, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}

	var findings []Finding

	for _, run := range report.Runs {
		ri := buildRuleIndex(run.Tool.Driver.Rules)

		for _, result := range run.Results {
			finding := extractFindingWithIndex(result, ri)
			finding.Fingerprint = GenerateFingerprint(finding)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// GenerateFingerprint creates a SHA256 hash of file + start line + rule ID for deduplication.
func GenerateFingerprint(f Finding) string {
	data := fmt.Sprintf("%s:%d:%s", f.FilePath, f.StartLine, f.RuleID)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// ruleIndex holds both the ID-based lookup map and the original slice for index-based access.
type ruleIndex struct {
	byID  map[string]ReportingDescriptor
	byIdx []ReportingDescriptor
}

// buildRuleIndex creates a lookup structure for rules supporting both ID and index-based access.
func buildRuleIndex(rules []ReportingDescriptor) ruleIndex {
	m := make(map[string]ReportingDescriptor, len(rules))
	for _, rule := range rules {
		m[rule.ID] = rule
	}
	return ruleIndex{byID: m, byIdx: rules}
}

// lookupRule finds a rule by ID or index, per SARIF spec.
// If ruleID is empty, falls back to ruleIndex.
func (ri ruleIndex) lookupRule(ruleID string, ruleIdx *int) (ReportingDescriptor, bool) {
	if ruleID != "" {
		if rule, ok := ri.byID[ruleID]; ok {
			return rule, true
		}
	}
	if ruleIdx != nil && *ruleIdx >= 0 && *ruleIdx < len(ri.byIdx) {
		return ri.byIdx[*ruleIdx], true
	}
	return ReportingDescriptor{}, false
}

// extractFindingWithIndex converts a single SARIF Result into a Finding.
// Only the first location is used; multiple locations are not supported (per design, as Finding is a flat struct).
func extractFindingWithIndex(result Result, ri ruleIndex) Finding {
	ruleID := result.RuleID
	// Per SARIF spec, if ruleID is empty, use ruleIndex to look up the rule and get its ID.
	if ruleID == "" && result.RuleIndex != nil {
		if rule, ok := ri.lookupRule("", result.RuleIndex); ok {
			ruleID = rule.ID
		}
	}

	f := Finding{
		RuleID:   ruleID,
		Message:  result.Message.Text,
		Severity: normalizeSeverity(result.Level),
	}

	// Extract location info from the first location only.
	// Note: Multiple locations are silently ignored; Finding is a flat struct by design.
	if len(result.Locations) > 0 {
		loc := result.Locations[0]
		if loc.PhysicalLocation != nil {
			pl := loc.PhysicalLocation

			if pl.ArtifactLocation != nil {
				f.FilePath = pl.ArtifactLocation.URI
			}

			if pl.Region != nil {
				if pl.Region.StartLine != nil {
					f.StartLine = *pl.Region.StartLine
				}
				if pl.Region.EndLine != nil {
					f.EndLine = *pl.Region.EndLine
				} else {
					f.EndLine = f.StartLine
				}
				if pl.Region.Snippet != nil {
					f.Snippet = pl.Region.Snippet.Text
				}
			}
		}
	}

	// Extract CWE, rule name, and fallback severity from rule metadata.
	if rule, ok := ri.lookupRule(result.RuleID, result.RuleIndex); ok {
		f.CWE = extractCWE(rule)
		if f.Severity == "unknown" {
			f.Severity = extractSeverityFromRule(rule)
		}
		f.RuleName = extractRuleName(rule)
	}

	return f
}

// extractRuleName returns the most useful human-readable rule title.
// Prefers reportingDescriptor.name (CodeQL convention), falls back to
// shortDescription.text (Semgrep registry, commercial scanners). Both
// may be empty for minimal SARIF producers — callers handle "".
func extractRuleName(rule ReportingDescriptor) string {
	if rule.Name != "" {
		return rule.Name
	}
	if rule.ShortDescription != nil && rule.ShortDescription.Text != "" {
		return rule.ShortDescription.Text
	}
	return ""
}

// cweExtract matches CWE IDs in various formats:
//   - "CWE-89", "CWE:89", "CWE89"
//   - "CWE-89: Improper Neutralization of Special Elements..."
//   - "external/cwe/cwe-798" (CodeQL/GitHub convention)
var cweExtract = regexp.MustCompile(`(?i)(?:^|/)cwe[-:]?(\d+)`)

// extractCWE extracts CWE ID from rule properties, relationships, or tags.
func extractCWE(rule ReportingDescriptor) string {
	// Check direct CWE property
	if rule.Properties != nil && rule.Properties.CWE != "" {
		return normalizeCWE(rule.Properties.CWE)
	}

	// Check relationships for CWE taxonomy references
	for _, rel := range rule.Relationships {
		if rel.Target != nil && rel.Target.ID != "" {
			if cwe := normalizeCWE(rel.Target.ID); cwe != "" {
				return cwe
			}
		}
	}

	// Check tags for CWE
	if rule.Properties != nil {
		for _, tag := range rule.Properties.Tags {
			if cwe := normalizeCWE(tag); cwe != "" {
				return cwe
			}
		}
	}

	return ""
}

// normalizeCWE extracts a CWE ID from various string formats into "CWE-XXX".
func normalizeCWE(cwe string) string {
	if cwe == "" {
		return ""
	}
	if matches := cweExtract.FindStringSubmatch(cwe); len(matches) > 1 {
		return "CWE-" + matches[1]
	}
	return ""
}

// normalizeSeverity maps SARIF level to normalized severity.
func normalizeSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	case "none":
		return "info"
	case "":
		return "unknown"
	default:
		return level
	}
}

// extractSeverityFromRule extracts severity from rule default configuration.
func extractSeverityFromRule(rule ReportingDescriptor) string {
	if rule.DefaultConfig != nil && rule.DefaultConfig.Level != "" {
		return normalizeSeverity(rule.DefaultConfig.Level)
	}
	return ""
}
