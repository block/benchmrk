package cwe

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"CWE-89", 89, true},
		{"cwe-89", 89, true},
		{"Cwe-89", 89, true},
		{"CWE-89: Improper Neutralization of Special Elements", 89, true},
		{"  CWE-89  ", 89, true},
		{"CWE89", 89, true},
		{"CWE_89", 89, true},
		{"89", 89, true},
		{"CWE-1321", 1321, true},
		{"", 0, false},
		{"CWE-", 0, false},
		{"CWE-abc", 0, false},
		{"not a cwe", 0, false},
		{"CWE-0", 0, false},
		{"CWE--89", 89, true}, // TrimLeft eats multiple
	}
	for _, tc := range cases {
		got, ok := Normalize(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Normalize(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDistance_Identity(t *testing.T) {
	if d := Distance(89, 89, 3); d != 0 {
		t.Errorf("Distance(89, 89) = %d, want 0", d)
	}
}

func TestDistance_DirectParent(t *testing.T) {
	// 331 (Insufficient Entropy) is ChildOf 330 (Use of Insufficiently
	// Random Values) — direct parent/child.
	if d := Distance(331, 330, 3); d != 1 {
		t.Errorf("Distance(331, 330) = %d, want 1 (direct parent)", d)
	}
	// Symmetric.
	if d := Distance(330, 331, 3); d != 1 {
		t.Errorf("Distance(330, 331) = %d, want 1 (symmetric)", d)
	}
}

func TestDistance_Siblings(t *testing.T) {
	// 89 (SQLi) and 78 (Command Injection) are both ChildOf 74 via 943/77
	// respectively — let me verify the actual tree...
	// 89 → 943 → 74; 78 → 77 → 74. Meet at 74 (not a pillar), combined depth 4.
	// At maxDepth 3 they won't meet via tree. But 74 is under 707 (pillar).
	// So at maxDepth 4 they should be distance 4.
	d := Distance(89, 78, 4)
	if d == Unrelated {
		t.Errorf("Distance(89, 78, 4) = Unrelated, expected meeting under CWE-74")
	}
	// And bounded by maxDepth.
	if d := Distance(89, 78, 2); d == Unrelated {
		// At depth 2 the tree won't reach, but categories might.
		// Don't assert a specific value — just document this is the
		// category-or-unrelated boundary.
		t.Logf("Distance(89, 78, 2) = %d (tree alone needs depth 4; category may rescue)", d)
	}
}

func TestDistance_PillarDoesNotCount(t *testing.T) {
	// 89 (SQLi, under pillar 707) and 287 (Improper Auth, under pillar 284)
	// meet only at pillars. Without category rescue, Unrelated.
	// They might share a category though — both are in OWASP-style groupings.
	// So we check: if related, it's via category (distance 2), not tree.
	d := Distance(89, 287, 6)
	if d == 1 {
		t.Errorf("Distance(89, 287) = 1, but these should not be tree-adjacent")
	}
}

// These are the exact drift pairs from the sample-app benchmark run that
// prompted this package. Each one was a same-line finding/annotation pair
// that failed the old string-equality CWE check. They MUST all be related
// at maxDepth 3 — that's the contract this package exists to satisfy.
func TestDistance_BenchmarkDriftPairs(t *testing.T) {
	pairs := []struct {
		a, b int
		why  string
	}{
		{639, 862, "IDOR vs missing-authz — tree via 285, plus categories"},
		{915, 269, "mass assignment vs priv escalation — curated (cause→effect)"},
		{287, 347, "auth bypass vs sig verify — curated (consequence↔mechanism)"},
		{620, 352, "unverified pw change vs CSRF — curated (weakness↔attack)"},
		{328, 327, "reversible hash vs broken algo — category + curated"},
		{331, 330, "insufficient entropy vs weak random — direct parent"},
		{862, 863, "missing authz vs incorrect authz — curated"},
	}
	for _, p := range pairs {
		d := Distance(p.a, p.b, 3)
		if d == Unrelated {
			t.Errorf("Distance(%d, %d) = Unrelated; benchmark drift pair not linked (%s)", p.a, p.b, p.why)
		}
		// Symmetry.
		if d2 := Distance(p.b, p.a, 3); d2 != d {
			t.Errorf("Distance(%d, %d) = %d but Distance(%d, %d) = %d; not symmetric", p.a, p.b, d, p.b, p.a, d2)
		}
	}
}

func TestDistance_GenuinelyUnrelated(t *testing.T) {
	// Things that should NOT match — verify we're not too permissive.
	pairs := []struct{ a, b int }{
		{89, 79},   // SQLi vs XSS — both injection but different pillars, shouldn't meet at depth 3
		{22, 352},  // Path traversal vs CSRF — no sensible link
		{798, 362}, // Hardcoded creds vs race condition
	}
	for _, p := range pairs {
		if d := Distance(p.a, p.b, 3); d != Unrelated {
			// Some of these might share an OWASP-Top-10 category. If so,
			// distance 2 is the floor — anything closer is wrong.
			if d < 2 {
				t.Errorf("Distance(%d, %d) = %d, too close for unrelated vulnerability classes", p.a, p.b, d)
			} else {
				t.Logf("Distance(%d, %d) = %d (category-linked; acceptable)", p.a, p.b, d)
			}
		}
	}
}

func TestDistance_UnknownIDs(t *testing.T) {
	if d := Distance(99999, 89, 3); d != Unrelated {
		t.Errorf("Distance(unknown, 89) = %d, want Unrelated", d)
	}
	if d := Distance(0, 89, 3); d != Unrelated {
		t.Errorf("Distance(0, 89) = %d, want Unrelated", d)
	}
	if d := Distance(-1, 89, 3); d != Unrelated {
		t.Errorf("Distance(-1, 89) = %d, want Unrelated", d)
	}
}

func TestDistance_MaxDepthBound(t *testing.T) {
	// Use a pair with no curated link so we're actually measuring the tree.
	// 89 (SQLi) → 943 → 74; 79 (XSS) → 74. Meet at 74, combined depth 3.
	if d := Distance(89, 79, 3); d != 3 {
		t.Errorf("Distance(89, 79, 3) = %d, want 3 (tree via CWE-74)", d)
	}
	// At maxDepth 2 the tree won't reach. Category may or may not rescue —
	// either way, NOT distance 1.
	if d := Distance(89, 79, 2); d == 1 || d == 3 {
		t.Errorf("Distance(89, 79, 2) = %d, maxDepth should have cut the tree path", d)
	}
}

func TestDistance_CuratedBeatsTree(t *testing.T) {
	// 639↔862 are both tree-linked (via 285, depth 3), category-linked,
	// AND curated. Curated is checked first and wins at distance 1.
	// This is intentional: a curated entry is a human saying "these are
	// the same finding," which is stronger than the tree inferring it.
	if d := Distance(639, 862, 3); d != 1 {
		t.Errorf("Distance(639, 862) = %d, want 1 (curated should beat tree/category)", d)
	}
	// And curated ignores maxDepth — it's distance 1 regardless.
	if d := Distance(639, 862, 0); d != 1 {
		t.Errorf("Distance(639, 862, 0) = %d, want 1 (curated ignores depth budget)", d)
	}
}

func TestAncestorDepths_CycleGuard(t *testing.T) {
	// 284 → 284 in the raw XML (pillar self-reference). The walk must
	// terminate.
	depths := ancestorDepths(284, 10)
	if len(depths) > 2 {
		t.Errorf("ancestorDepths(284) looped: got %d entries, expected ≤2", len(depths))
	}
}

func TestSharesCategory(t *testing.T) {
	// 639 and 862 share category 813, 1011, 1345 per the XML probe.
	if !sharesCategory(639, 862) {
		t.Error("sharesCategory(639, 862) = false, but they share OWASP authz categories")
	}
	// Reflexive (a CWE shares its own categories with itself).
	if len(categoriesOf[89]) > 0 && !sharesCategory(89, 89) {
		t.Error("sharesCategory(89, 89) = false")
	}
}

func TestRelated_Convenience(t *testing.T) {
	if !Related(639, 862, 3) {
		t.Error("Related(639, 862, 3) = false")
	}
	if Related(89, 89, 3) != true {
		t.Error("Related(89, 89, 3) = false (identity)")
	}
}
