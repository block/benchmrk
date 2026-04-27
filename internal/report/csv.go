package report

import (
	"encoding/csv"
	"fmt"
	"io"
)

// FormatCSV writes the report as CSV format.
func FormatCSV(data *ReportData, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	headers := []string{
		"Scanner",
		"Project",
		"TP",
		"FP",
		"FN",
		"TN",
		"Precision",
		"Recall",
		"F1",
		"Accuracy",
		"AvgDuration",
		"PeakMemory",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("write headers: %w", err)
	}

	for _, sr := range data.ByScanner {
		for _, pr := range sr.ByProject {
			row := []string{
				sr.ScannerName,
				pr.ProjectName,
				fmt.Sprintf("%d", pr.TP),
				fmt.Sprintf("%d", pr.FP),
				fmt.Sprintf("%d", pr.FN),
				fmt.Sprintf("%d", pr.TN),
				fmt.Sprintf("%.4f", pr.Precision),
				fmt.Sprintf("%.4f", pr.Recall),
				fmt.Sprintf("%.4f", pr.F1),
				fmt.Sprintf("%.4f", pr.Accuracy),
				fmt.Sprintf("%d", pr.DurationMs),
				fmt.Sprintf("%d", pr.MemoryBytes),
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("write row: %w", err)
			}
		}
	}

	return writer.Error()
}
