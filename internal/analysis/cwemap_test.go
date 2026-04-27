package analysis

import "testing"

func TestCWE89AndCWE564MapToSameCategory(t *testing.T) {
	cat89 := GetCategory("CWE-89")
	cat564 := GetCategory("CWE-564")

	if cat89 != "sql-injection" {
		t.Errorf("GetCategory(CWE-89) = %q, want sql-injection", cat89)
	}
	if cat564 != "sql-injection" {
		t.Errorf("GetCategory(CWE-564) = %q, want sql-injection", cat564)
	}
	if cat89 != cat564 {
		t.Errorf("CWE-89 and CWE-564 should map to same category, got %q and %q", cat89, cat564)
	}
}

func TestGetCategoryUnknownCWE(t *testing.T) {
	cat := GetCategory("CWE-99999")
	if cat != "unknown" {
		t.Errorf("GetCategory(CWE-99999) = %q, want unknown", cat)
	}
}

func TestAreCompatibleSameCategoryCWEs(t *testing.T) {
	// CWE-89 and CWE-564 are both sql-injection
	if !AreCompatible("CWE-89", "CWE-564") {
		t.Error("AreCompatible(CWE-89, CWE-564) = false, want true (both sql-injection)")
	}

	// CWE-79 and CWE-80 are both xss
	if !AreCompatible("CWE-79", "CWE-80") {
		t.Error("AreCompatible(CWE-79, CWE-80) = false, want true (both xss)")
	}
}

func TestAreCompatibleDifferentCategoryCWEs(t *testing.T) {
	// CWE-89 (sql-injection) vs CWE-79 (xss)
	if AreCompatible("CWE-89", "CWE-79") {
		t.Error("AreCompatible(CWE-89, CWE-79) = true, want false (different categories)")
	}

	// CWE-78 (command-injection) vs CWE-22 (path-traversal)
	if AreCompatible("CWE-78", "CWE-22") {
		t.Error("AreCompatible(CWE-78, CWE-22) = true, want false (different categories)")
	}
}

func TestAreCompatibleUnknownCWEsNotCompatible(t *testing.T) {
	// Unknown CWEs should not be considered compatible
	if AreCompatible("CWE-99999", "CWE-99998") {
		t.Error("AreCompatible(CWE-99999, CWE-99998) = true, want false (unknown CWEs)")
	}

	// Known vs unknown
	if AreCompatible("CWE-89", "CWE-99999") {
		t.Error("AreCompatible(CWE-89, CWE-99999) = true, want false (one unknown)")
	}
}

func TestGetCategoryCoversCommonVulnerabilities(t *testing.T) {
	tests := []struct {
		cwe      string
		expected string
	}{
		{"CWE-89", "sql-injection"},
		{"CWE-79", "xss"},
		{"CWE-78", "command-injection"},
		{"CWE-22", "path-traversal"},
		{"CWE-502", "deserialization"},
		{"CWE-327", "weak-crypto"},
		{"CWE-611", "xxe"},
		{"CWE-918", "ssrf"},
		{"CWE-601", "open-redirect"},
		{"CWE-352", "csrf"},
		{"CWE-798", "hardcoded-credentials"},
		{"CWE-120", "memory-corruption"},
		{"CWE-416", "use-after-free"},
		{"CWE-190", "integer-overflow"},
		{"CWE-362", "race-condition"},
	}

	for _, tt := range tests {
		t.Run(tt.cwe, func(t *testing.T) {
			got := GetCategory(tt.cwe)
			if got != tt.expected {
				t.Errorf("GetCategory(%s) = %q, want %q", tt.cwe, got, tt.expected)
			}
		})
	}
}
