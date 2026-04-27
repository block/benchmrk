package report

import (
	"encoding/json"
	"io"

	"github.com/block/benchmrk/internal/sarif"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
)

// FormatSARIF writes the report as SARIF 2.1.0 JSON format.
func FormatSARIF(data *ReportData, w io.Writer) error {
	report := sarif.SarifReport{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    make([]sarif.Run, 0, len(data.ByScanner)),
	}

	for _, sr := range data.ByScanner {
		run := sarif.Run{
			Tool: sarif.Tool{
				Driver: sarif.ToolComponent{
					Name:    sr.ScannerName,
					Version: getScannerVersion(data.Scanners, sr.ScannerID),
					Rules:   buildRulesFromCategories(data.ByCategory),
				},
			},
			Results: buildResultsFromScanner(sr, data.ByCategory),
		}
		report.Runs = append(report.Runs, run)
	}

	if len(report.Runs) == 0 {
		report.Runs = []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: sarif.ToolComponent{
						Name:    "benchmrk",
						Version: "1.0.0",
					},
				},
				Results: []sarif.Result{},
			},
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func getScannerVersion(scanners []ScannerInfo, scannerID int64) string {
	for _, s := range scanners {
		if s.ID == scannerID {
			return s.Version
		}
	}
	return ""
}

func buildRulesFromCategories(categories []CategoryStats) []sarif.ReportingDescriptor {
	rules := make([]sarif.ReportingDescriptor, 0, len(categories))
	for _, cat := range categories {
		rules = append(rules, sarif.ReportingDescriptor{
			ID:   cat.Category,
			Name: cat.Category,
			ShortDescription: &sarif.Message{
				Text: cat.Category,
			},
			Properties: &sarif.PropertyBag{
				Tags: []string{"security"},
			},
		})
	}
	return rules
}

func buildResultsFromScanner(sr ScannerResult, categories []CategoryStats) []sarif.Result {
	results := make([]sarif.Result, 0)

	for _, pr := range sr.ByProject {
		if pr.TP > 0 {
			ruleIndex := 0
			results = append(results, sarif.Result{
				RuleID:    "finding",
				RuleIndex: &ruleIndex,
				Level:     "warning",
				Message: sarif.Message{
					Text: formatFindingMessage(pr),
				},
				Locations: []sarif.Location{
					{
						PhysicalLocation: &sarif.PhysicalLocation{
							ArtifactLocation: &sarif.ArtifactLocation{
								URI: pr.ProjectName,
							},
						},
					},
				},
				PartialFingerprints: map[string]string{
					"benchmrk/project": pr.ProjectName,
					"benchmrk/scanner": sr.ScannerName,
				},
			})
		}
	}

	return results
}

func formatFindingMessage(pr ProjectResult) string {
	return "Analysis results for " + pr.ProjectName +
		": TP=" + itoa(pr.TP) +
		", FP=" + itoa(pr.FP) +
		", FN=" + itoa(pr.FN) +
		", TN=" + itoa(pr.TN)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
