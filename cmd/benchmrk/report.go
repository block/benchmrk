package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/block/benchmrk/internal/analysis"
	"github.com/block/benchmrk/internal/report"
	"github.com/spf13/cobra"
)

var (
	reportFormat string
	reportOutput string
)

var reportCmd = &cobra.Command{
	Use:   "report <experiment-id>",
	Short: "Generate a report for an experiment",
	Long:  "Generate a benchmark report for an experiment in the specified format(s).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		experimentID, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid experiment ID: %w", err)
		}

		if globalStore == nil {
			return fmt.Errorf("store not initialized")
		}

		formats, err := parseFormats(reportFormat)
		if err != nil {
			return err
		}

		analysisSvc := analysis.NewService(globalStore, nil)
		reportSvc := report.NewService(globalStore, analysisSvc)

		data, err := reportSvc.GenerateReportData(cmd.Context(), experimentID)
		if err != nil {
			return fmt.Errorf("generate report data: %w", err)
		}

		return writeReports(data, formats, reportOutput)
	},
}

func parseFormats(formatStr string) ([]string, error) {
	parts := strings.Split(formatStr, ",")
	formats := make([]string, 0, len(parts))

	validFormats := map[string]bool{
		"md":       true,
		"markdown": true,
		"json":     true,
		"csv":      true,
		"html":     true,
		"sarif":    true,
	}

	for _, p := range parts {
		f := strings.TrimSpace(strings.ToLower(p))
		if f == "" {
			continue
		}
		if !validFormats[f] {
			return nil, fmt.Errorf("invalid format %q: supported formats are md, json, csv, html, sarif", f)
		}
		if f == "markdown" {
			f = "md"
		}
		formats = append(formats, f)
	}

	if len(formats) == 0 {
		formats = []string{"md"}
	}

	return formats, nil
}

func writeReports(data *report.ReportData, formats []string, outputDir string) error {
	if len(formats) == 1 && outputDir == "" {
		return writeReport(data, formats[0], os.Stdout)
	}

	if outputDir == "" {
		outputDir = "."
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	for _, format := range formats {
		ext := format
		if format == "md" {
			ext = "md"
		}
		filename := filepath.Join(outputDir, fmt.Sprintf("report.%s", ext))
		f, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("create %s: %w", filename, err)
		}

		if err := writeReport(data, format, f); err != nil {
			f.Close()
			return fmt.Errorf("write %s: %w", format, err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", filename, err)
		}

		fmt.Printf("Generated: %s\n", filename)
	}

	return nil
}

func writeReport(data *report.ReportData, format string, w io.Writer) error {
	switch format {
	case "md", "markdown":
		return report.FormatMarkdown(data, w)
	case "json":
		return report.FormatJSON(data, w)
	case "csv":
		return report.FormatCSV(data, w)
	case "html":
		return report.FormatHTML(data, w)
	case "sarif":
		return report.FormatSARIF(data, w)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func init() {
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "md", "output format(s): md, json, csv, html, sarif (comma-separated for multiple)")
	reportCmd.Flags().StringVarP(&reportOutput, "output", "o", "", "output directory (default: stdout for single format, current dir for multiple)")

	rootCmd.AddCommand(reportCmd)
}
