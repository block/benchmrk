package sarif

import (
	"strings"
	"testing"
)

func TestValidate_ValidReport(t *testing.T) {
	report, err := Parse(strings.NewReader(validSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	errs := Validate(report)
	if len(errs) != 0 {
		t.Errorf("Validate() returned %d errors for valid report: %v", len(errs), errs)
	}
}

func TestValidate_NilReport(t *testing.T) {
	errs := Validate(nil)
	if len(errs) != 1 {
		t.Errorf("Validate(nil) should return 1 error, got %d", len(errs))
	}
	if !strings.Contains(errs[0].Error(), "nil") {
		t.Errorf("Error should mention nil: %v", errs[0])
	}
}

func TestValidate_WrongVersion(t *testing.T) {
	wrongVersionSARIF := `{
		"version": "2.0.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "Scanner"
					}
				}
			}
		]
	}`

	report, err := Parse(strings.NewReader(wrongVersionSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	errs := Validate(report)
	if len(errs) == 0 {
		t.Error("Validate() should return error for wrong version")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "version") && strings.Contains(e.Error(), "2.0.0") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected version error, got: %v", errs)
	}
}

func TestValidate_MissingRuns(t *testing.T) {
	missingRunsSARIF := `{
		"version": "2.1.0",
		"runs": []
	}`

	report, err := Parse(strings.NewReader(missingRunsSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	errs := Validate(report)
	if len(errs) == 0 {
		t.Error("Validate() should return error for missing runs")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "at least one run") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected missing runs error, got: %v", errs)
	}
}

func TestValidate_MissingToolName(t *testing.T) {
	missingToolNameSARIF := `{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {}
				}
			}
		]
	}`

	report, err := Parse(strings.NewReader(missingToolNameSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	errs := Validate(report)
	if len(errs) == 0 {
		t.Error("Validate() should return error for missing tool name")
	}

	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "tool driver name") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected missing tool name error, got: %v", errs)
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	badSARIF := `{
		"version": "1.0.0",
		"runs": []
	}`

	report, err := Parse(strings.NewReader(badSARIF))
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	errs := Validate(report)
	if len(errs) < 2 {
		t.Errorf("Validate() should return multiple errors, got %d: %v", len(errs), errs)
	}
}
