package report

import (
	"encoding/json"
	"io"
)

// FormatJSON writes the report as pretty-printed JSON.
func FormatJSON(data *ReportData, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}
