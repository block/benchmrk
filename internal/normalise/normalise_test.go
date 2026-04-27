package normalise

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/block/benchmrk/internal/sarif"
)

// mockConverter is a test converter that returns a fixed report.
type mockConverter struct {
	report *sarif.SarifReport
	err    error
}

func (m *mockConverter) Convert(r io.Reader) (*sarif.SarifReport, error) {
	return m.report, m.err
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	conv := &mockConverter{report: &sarif.SarifReport{Version: "2.1.0"}}

	reg.Register("test-format", conv)

	got, ok := reg.Get("test-format")
	if !ok {
		t.Fatal("expected converter to be found")
	}
	if got != conv {
		t.Error("expected same converter instance")
	}
}

func TestRegistry_GetUnknown(t *testing.T) {
	reg := NewRegistry()

	_, ok := reg.Get("nonexistent")
	if ok {
		t.Error("expected false for unknown format")
	}
}

func TestRegistry_Convert(t *testing.T) {
	reg := NewRegistry()
	expected := &sarif.SarifReport{Version: "2.1.0"}
	reg.Register("test", &mockConverter{report: expected})

	got, err := reg.Convert("test", strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != "2.1.0" {
		t.Errorf("expected version '2.1.0', got %q", got.Version)
	}
}

func TestRegistry_Convert_UnknownFormat(t *testing.T) {
	reg := NewRegistry()

	_, err := reg.Convert("nonexistent", strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "no converter registered") {
		t.Errorf("expected 'no converter registered' error, got: %v", err)
	}
}

func TestRegistry_Convert_ConverterError(t *testing.T) {
	reg := NewRegistry()
	reg.Register("failing", &mockConverter{err: fmt.Errorf("parse failed")})

	_, err := reg.Convert("failing", strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error from converter")
	}
	if !strings.Contains(err.Error(), "parse failed") {
		t.Errorf("expected 'parse failed' error, got: %v", err)
	}
}

func TestRegistry_Formats(t *testing.T) {
	reg := NewRegistry()
	reg.Register("format-a", &mockConverter{})
	reg.Register("format-b", &mockConverter{})

	formats := reg.Formats()
	sort.Strings(formats)

	if len(formats) != 2 {
		t.Fatalf("expected 2 formats, got %d", len(formats))
	}
	if formats[0] != "format-a" || formats[1] != "format-b" {
		t.Errorf("expected [format-a format-b], got %v", formats)
	}
}

func TestSarifConverter_ValidSARIF(t *testing.T) {
	input := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "TestScanner", "version": "1.0"}},
			"results": [
				{
					"ruleId": "rule-1",
					"level": "warning",
					"message": {"text": "Test finding"},
					"locations": [{
						"physicalLocation": {
							"artifactLocation": {"uri": "file.py"},
							"region": {"startLine": 10}
						}
					}]
				}
			]
		}]
	}`

	conv := &SarifConverter{}
	report, err := conv.Convert(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Errorf("expected version '2.1.0', got %q", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Runs[0].Results))
	}
	if report.Runs[0].Results[0].RuleID != "rule-1" {
		t.Errorf("expected ruleId 'rule-1', got %q", report.Runs[0].Results[0].RuleID)
	}
}

func TestSarifConverter_InvalidJSON(t *testing.T) {
	conv := &SarifConverter{}
	_, err := conv.Convert(strings.NewReader("{invalid"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewDefaultRegistry(t *testing.T) {
	reg := NewDefaultRegistry()

	// Should have "sarif" registered
	_, ok := reg.Get("sarif")
	if !ok {
		t.Error("expected 'sarif' converter in default registry")
	}

	// Verify it works end-to-end
	input := `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Test"}}, "results": []}]}`
	report, err := reg.Convert("sarif", strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Version != "2.1.0" {
		t.Errorf("expected version '2.1.0', got %q", report.Version)
	}
}
