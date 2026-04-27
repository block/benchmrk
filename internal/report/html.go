package report

import (
	"html/template"
	"io"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        h3 { color: #7f8c8d; }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .card-value { font-size: 24px; font-weight: bold; color: #2980b9; }
        .card-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }
        th {
            background: #3498db;
            color: white;
            font-weight: 600;
        }
        tr:hover { background: #f8f9fa; }
        .metric-good { color: #27ae60; }
        .metric-bad { color: #e74c3c; }
        .metric-neutral { color: #7f8c8d; }
        .experiment-info { background: white; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .experiment-info p { margin: 5px 0; }
        .generated { color: #95a5a6; font-size: 14px; }
        .delta-positive { color: #27ae60; }
        .delta-negative { color: #e74c3c; }
        .empty-message { color: #95a5a6; font-style: italic; padding: 20px; text-align: center; }
        details { margin: 10px 0; }
        summary { cursor: pointer; padding: 10px; background: #ecf0f1; border-radius: 5px; }
        summary:hover { background: #dfe6e9; }
    </style>
</head>
<body>
    <h1>{{.Title}}</h1>
    <p class="generated">Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}</p>

    <div class="experiment-info">
        <h2>Experiment</h2>
        <p><strong>Name:</strong> {{.Experiment.Name}}</p>
        {{if .Experiment.Description}}<p><strong>Description:</strong> {{.Experiment.Description}}</p>{{end}}
        <p><strong>Iterations:</strong> {{.Experiment.Iterations}}</p>
        <p><strong>Scanners:</strong> {{len .Scanners}}</p>
        <p><strong>Projects:</strong> {{len .Projects}}</p>
    </div>

    <h2>Summary</h2>
    <div class="summary-cards">
        <div class="card">
            <div class="card-value">{{.Summary.TotalRuns}}</div>
            <div class="card-label">Total Runs</div>
        </div>
        <div class="card">
            <div class="card-value">{{.Summary.TotalFindings}}</div>
            <div class="card-label">Total Findings</div>
        </div>
        <div class="card">
            <div class="card-value">{{.Summary.TotalTP}}</div>
            <div class="card-label">True Positives</div>
        </div>
        <div class="card">
            <div class="card-value">{{.Summary.TotalFP}}</div>
            <div class="card-label">False Positives</div>
        </div>
        <div class="card">
            <div class="card-value">{{.Summary.TotalFN}}</div>
            <div class="card-label">False Negatives</div>
        </div>
        <div class="card">
            <div class="card-value">{{.Summary.TotalTN}}</div>
            <div class="card-label">True Negatives</div>
        </div>
        <div class="card">
            <div class="card-value">{{printf "%.1f%%" (mult .Summary.AvgPrecision 100)}}</div>
            <div class="card-label">Avg Precision</div>
        </div>
        <div class="card">
            <div class="card-value">{{printf "%.1f%%" (mult .Summary.AvgRecall 100)}}</div>
            <div class="card-label">Avg Recall</div>
        </div>
        <div class="card">
            <div class="card-value">{{printf "%.1f%%" (mult .Summary.AvgF1 100)}}</div>
            <div class="card-label">Avg F1</div>
        </div>
        <div class="card">
            <div class="card-value">{{printf "%.1f%%" (mult .Summary.AvgAccuracy 100)}}</div>
            <div class="card-label">Avg Accuracy</div>
        </div>
    </div>

    <h2>Scanner Results</h2>
    {{if .ByScanner}}
    <table>
        <thead>
            <tr>
                <th>Scanner</th>
                <th>Runs</th>
                <th>TP</th>
                <th>FP</th>
                <th>FN</th>
                <th>TN</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1</th>
                <th>Accuracy</th>
            </tr>
        </thead>
        <tbody>
            {{range .ByScanner}}
            <tr>
                <td>{{.ScannerName}}</td>
                <td>{{.RunCount}}</td>
                <td>{{.Metrics.TP}}</td>
                <td>{{.Metrics.FP}}</td>
                <td>{{.Metrics.FN}}</td>
                <td>{{.Metrics.TN}}</td>
                <td>{{printf "%.2f%%" (mult .Metrics.Precision 100)}}</td>
                <td>{{printf "%.2f%%" (mult .Metrics.Recall 100)}}</td>
                <td>{{printf "%.2f%%" (mult .Metrics.F1 100)}}</td>
                <td>{{printf "%.2f%%" (mult .Metrics.Accuracy 100)}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>

    {{range .ByScanner}}
    {{if .ByProject}}
    <h3>{{.ScannerName}} - Per Project</h3>
    <table>
        <thead>
            <tr>
                <th>Project</th>
                <th>TP</th>
                <th>FP</th>
                <th>FN</th>
                <th>TN</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1</th>
                <th>Accuracy</th>
                <th>Duration (ms)</th>
            </tr>
        </thead>
        <tbody>
            {{range .ByProject}}
            <tr>
                <td>{{.ProjectName}}</td>
                <td>{{.TP}}</td>
                <td>{{.FP}}</td>
                <td>{{.FN}}</td>
                <td>{{.TN}}</td>
                <td>{{printf "%.2f%%" (mult .Precision 100)}}</td>
                <td>{{printf "%.2f%%" (mult .Recall 100)}}</td>
                <td>{{printf "%.2f%%" (mult .F1 100)}}</td>
                <td>{{printf "%.2f%%" (mult .Accuracy 100)}}</td>
                <td>{{.DurationMs}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>

    {{range .ByProject}}
    {{if .Annotations}}
    <details>
        <summary><strong>{{.ProjectName}} — Annotation Coverage ({{len .Annotations}} annotations)</strong></summary>

        <h4>Triggered (Detected)</h4>
        <table>
            <thead>
                <tr><th>File</th><th>Line</th><th>CWE</th><th>Category</th><th>Severity</th><th>Match</th><th>Confidence</th><th>Result</th></tr>
            </thead>
            <tbody>
                {{range .Annotations}}{{if .Matched}}
                <tr>
                    <td>{{.FilePath}}</td>
                    <td>{{.StartLine}}</td>
                    <td>{{.CWEID}}</td>
                    <td>{{.Category}}</td>
                    <td>{{.Severity}}</td>
                    <td>{{.MatchType}}</td>
                    <td>{{printf "%.0f%%" (mult .Confidence 100)}}</td>
                    <td class="metric-good">{{.Classification}}</td>
                </tr>
                {{end}}{{end}}
            </tbody>
        </table>

        <h4>Missed (Not Detected)</h4>
        <table>
            <thead>
                <tr><th>File</th><th>Line</th><th>CWE</th><th>Category</th><th>Severity</th><th>Status</th><th>Result</th></tr>
            </thead>
            <tbody>
                {{range .Annotations}}{{if and (not .Matched) (eq .Status "valid")}}
                <tr>
                    <td>{{.FilePath}}</td>
                    <td>{{.StartLine}}</td>
                    <td>{{.CWEID}}</td>
                    <td>{{.Category}}</td>
                    <td>{{.Severity}}</td>
                    <td>{{.Status}}</td>
                    <td class="metric-bad">{{.Classification}}</td>
                </tr>
                {{end}}{{end}}
            </tbody>
        </table>

        {{if .UnmatchedFindings}}
        <h4>Unmatched Findings (False Positives)</h4>
        <table>
            <thead>
                <tr><th>File</th><th>Line</th><th>CWE</th><th>Rule</th><th>Severity</th></tr>
            </thead>
            <tbody>
                {{range .UnmatchedFindings}}
                <tr>
                    <td>{{.FilePath}}</td>
                    <td>{{.StartLine}}</td>
                    <td>{{.CWEID}}</td>
                    <td>{{.RuleID}}</td>
                    <td>{{.Severity}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
        {{end}}
    </details>
    {{end}}
    {{end}}

    {{end}}
    {{end}}
    {{else}}
    <p class="empty-message">No scanner results available.</p>
    {{end}}

    <h2>Category Breakdown</h2>
    {{if .ByCategory}}
    <table>
        <thead>
            <tr>
                <th>Category</th>
                <th>TP</th>
                <th>FP</th>
                <th>FN</th>
                <th>TN</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1</th>
                <th>Accuracy</th>
            </tr>
        </thead>
        <tbody>
            {{range .ByCategory}}
            <tr>
                <td>{{.Category}}</td>
                <td>{{.TP}}</td>
                <td>{{.FP}}</td>
                <td>{{.FN}}</td>
                <td>{{.TN}}</td>
                <td>{{printf "%.2f%%" (mult .Precision 100)}}</td>
                <td>{{printf "%.2f%%" (mult .Recall 100)}}</td>
                <td>{{printf "%.2f%%" (mult .F1 100)}}</td>
                <td>{{printf "%.2f%%" (mult .Accuracy 100)}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>
    {{else}}
    <p class="empty-message">No category data available.</p>
    {{end}}

    {{if .Comparison}}
    <h2>Scanner Comparison</h2>
    <p>Comparing {{len .Comparison.Entries}} scanners (baseline: {{(index .Comparison.Entries .Comparison.BaselineIndex).Scanner.Name}})</p>
    <div style="overflow-x: auto;">
    <table>
        <thead>
            <tr>
                <th>Metric</th>
                {{range .Comparison.Entries}}<th>{{.Scanner.Name}}</th>{{end}}
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Precision</td>
                {{range .Comparison.Entries}}
                <td>{{printf "%.2f%%" (mult .Metrics.Precision 100)}}{{if .Delta}} <span class="{{deltaClass .Delta.Precision}}">({{printf "%+.2f%%" (mult .Delta.Precision 100)}})</span>{{end}}</td>
                {{end}}
            </tr>
            <tr>
                <td>Recall</td>
                {{range .Comparison.Entries}}
                <td>{{printf "%.2f%%" (mult .Metrics.Recall 100)}}{{if .Delta}} <span class="{{deltaClass .Delta.Recall}}">({{printf "%+.2f%%" (mult .Delta.Recall 100)}})</span>{{end}}</td>
                {{end}}
            </tr>
            <tr>
                <td>F1</td>
                {{range .Comparison.Entries}}
                <td>{{printf "%.2f%%" (mult .Metrics.F1 100)}}{{if .Delta}} <span class="{{deltaClass .Delta.F1}}">({{printf "%+.2f%%" (mult .Delta.F1 100)}})</span>{{end}}</td>
                {{end}}
            </tr>
            <tr>
                <td>Accuracy</td>
                {{range .Comparison.Entries}}
                <td>{{printf "%.2f%%" (mult .Metrics.Accuracy 100)}}{{if .Delta}} <span class="{{deltaClass .Delta.Accuracy}}">({{printf "%+.2f%%" (mult .Delta.Accuracy 100)}})</span>{{end}}</td>
                {{end}}
            </tr>
            <tr>
                <td>Duration (ms)</td>
                {{range .Comparison.Entries}}
                <td>{{printf "%.0f" .Metrics.DurationMs}}{{if .Delta}} <span>({{printf "%+.0f" .Delta.DurationMs}})</span>{{end}}</td>
                {{end}}
            </tr>
        </tbody>
    </table>
    </div>

    {{if .Comparison.ByProject}}
    <h3>Per-Project Comparison</h3>
    <div style="overflow-x: auto;">
    <table>
        <thead>
            <tr>
                <th>Project</th>
                {{range .Comparison.Entries}}<th>{{.Scanner.Name}} F1</th>{{end}}
            </tr>
        </thead>
        <tbody>
            {{range .Comparison.ByProject}}
            <tr>
                <td>{{.ProjectName}}</td>
                {{range .Entries}}
                <td>{{printf "%.2f%%" (mult .F1 100)}}{{if .DeltaF1}} <span class="{{deltaClass (deref .DeltaF1)}}">({{printf "%+.2f%%" (mult (deref .DeltaF1) 100)}})</span>{{end}}</td>
                {{end}}
            </tr>
            {{end}}
        </tbody>
    </table>
    </div>
    {{end}}
    {{end}}
</body>
</html>`

// FormatHTML writes the report as a standalone HTML page.
func FormatHTML(data *ReportData, w io.Writer) error {
	funcMap := template.FuncMap{
		"mult": func(a, b float64) float64 {
			return a * b
		},
		"deltaClass": func(v float64) string {
			if v > 0 {
				return "delta-positive"
			} else if v < 0 {
				return "delta-negative"
			}
			return ""
		},
		"deref": func(p *float64) float64 {
			if p == nil {
				return 0
			}
			return *p
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	return tmpl.Execute(w, data)
}
