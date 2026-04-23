package report

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/benchmrk/internal/sarif"
	"github.com/block/benchmrk/internal/store"
)

// --- near-miss -------------------------------------------------------------

func TestNearMiss_Closest(t *testing.T) {
	// Two evidence rows in the same file; finding sits between them.
	// The closer one (by line) should win regardless of CWE fit.
	idx := buildNearMissIndex(
		[]store.Evidence{
			{ID: 1, VulnID: 10, FilePath: "app/auth.go", StartLine: 40},
			{ID: 2, VulnID: 11, FilePath: "app/auth.go", StartLine: 100},
		},
		map[int64]store.Vulnerability{
			10: {ID: 10, Name: "jwt-alg-none"},
			11: {ID: 11, Name: "session-fixation"},
		},
		map[int64][]string{
			10: {"CWE-347"},
			11: {"CWE-384"},
		},
	)

	f := store.Finding{
		FilePath:  "app/auth.go",
		StartLine: 50,
		CWEID:     sql.NullString{String: "CWE-347", Valid: true},
	}
	nm := idx.closest(f)
	if nm == nil {
		t.Fatal("expected near-miss, got nil")
	}
	if nm.Evidence.ID != 1 {
		t.Errorf("closest evidence = %d, want 1 (10 lines vs 50)", nm.Evidence.ID)
	}
	if nm.LineDelta != 10 {
		t.Errorf("LineDelta = %d, want 10", nm.LineDelta)
	}
	if nm.CWEDist != 0 {
		t.Errorf("CWEDist = %d, want 0 (exact CWE)", nm.CWEDist)
	}
	if !strings.Contains(nm.Why, "same CWE") || !strings.Contains(nm.Why, "outside fuzzy range") {
		t.Errorf("Why = %q, want same-CWE-outside-fuzzy explanation", nm.Why)
	}
}

func TestNearMiss_NoEvidenceInFile(t *testing.T) {
	idx := buildNearMissIndex(
		[]store.Evidence{{ID: 1, VulnID: 10, FilePath: "other.go", StartLine: 1}},
		map[int64]store.Vulnerability{10: {Name: "x"}},
		nil,
	)
	nm := idx.closest(store.Finding{FilePath: "auth.go", StartLine: 42})
	if nm != nil {
		t.Errorf("expected nil (no evidence in file), got %+v", nm)
	}
}

func TestNearMiss_PathNormalization(t *testing.T) {
	// Finding has /target/ container prefix, evidence doesn't. They
	// should still find each other.
	idx := buildNearMissIndex(
		[]store.Evidence{{ID: 1, VulnID: 10, FilePath: "src/db.go", StartLine: 20}},
		map[int64]store.Vulnerability{10: {Name: "sqli"}},
		nil,
	)
	nm := idx.closest(store.Finding{FilePath: "/target/src/db.go", StartLine: 22})
	if nm == nil {
		t.Fatal("expected near-miss across /target/ prefix, got nil")
	}
	if nm.LineDelta != 2 {
		t.Errorf("LineDelta = %d, want 2", nm.LineDelta)
	}
}

func TestNearMiss_CWETiebreak(t *testing.T) {
	// Two evidence rows equidistant from the finding. The one with the
	// better CWE relationship should win the tiebreak.
	idx := buildNearMissIndex(
		[]store.Evidence{
			{ID: 1, VulnID: 10, FilePath: "app.go", StartLine: 40},
			{ID: 2, VulnID: 11, FilePath: "app.go", StartLine: 60},
		},
		map[int64]store.Vulnerability{10: {Name: "unrelated"}, 11: {Name: "related"}},
		map[int64][]string{
			10: {"CWE-79"}, // XSS — unrelated to the finding's CWE
			11: {"CWE-89"}, // SQLi — exact
		},
	)
	f := store.Finding{
		FilePath:  "app.go",
		StartLine: 50, // 10 lines from both
		CWEID:     sql.NullString{String: "CWE-89", Valid: true},
	}
	nm := idx.closest(f)
	if nm == nil {
		t.Fatal("expected near-miss")
	}
	if nm.Evidence.ID != 2 {
		t.Errorf("evidence = %d, want 2 (CWE-related wins equidistant tiebreak)", nm.Evidence.ID)
	}
}

func TestExplainNearMiss(t *testing.T) {
	cases := []struct {
		name           string
		lineDelta, cwe int
		hasCWE         bool
		wantSubstr     string
	}{
		{"same line unrelated CWE", 0, -1, true, "same line, CWE unrelated"},
		{"same line no CWE", 0, -1, false, "greedy assignment"},
		{"fuzzy range related", 3, 1, true, "inside fuzzy range"},
		{"fuzzy range unrelated", 4, -1, true, "wrong bug class"},
		{"far same CWE", 13, 0, true, "outside fuzzy range"},
		{"far unrelated", 30, -1, true, "different bug"},
	}
	for _, tc := range cases {
		got := explainNearMiss(tc.lineDelta, tc.cwe, tc.hasCWE)
		if !strings.Contains(got, tc.wantSubstr) {
			t.Errorf("%s: explainNearMiss(%d, %d, %v) = %q, want substring %q",
				tc.name, tc.lineDelta, tc.cwe, tc.hasCWE, got, tc.wantSubstr)
		}
	}
}

// --- source context --------------------------------------------------------

func TestReadSourceContext(t *testing.T) {
	dir := t.TempDir()
	src := `package main

func main() {
	x := userInput()
	db.Query("SELECT * FROM t WHERE id=" + x)
	return
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	f := store.Finding{FilePath: "main.go", StartLine: 5}
	ctx := readSourceContext(dir, f, 2)
	if ctx == nil {
		t.Fatal("expected context, got nil")
	}
	if ctx.Language != "go" {
		t.Errorf("Language = %q, want go", ctx.Language)
	}
	// ±2 around line 5 → lines 3..7
	if len(ctx.Lines) != 5 {
		t.Fatalf("got %d lines, want 5", len(ctx.Lines))
	}
	if ctx.Lines[0].N != 3 || ctx.Lines[4].N != 7 {
		t.Errorf("line range = %d..%d, want 3..7", ctx.Lines[0].N, ctx.Lines[4].N)
	}
	// Only line 5 should be the target.
	for _, l := range ctx.Lines {
		if (l.N == 5) != l.Target {
			t.Errorf("line %d: Target = %v, want %v", l.N, l.Target, l.N == 5)
		}
	}
	if !strings.Contains(ctx.Lines[2].Text, "db.Query") {
		t.Errorf("line 5 = %q, expected the query", ctx.Lines[2].Text)
	}
}

func TestReadSourceContext_FileMissing(t *testing.T) {
	ctx := readSourceContext("/nonexistent", store.Finding{FilePath: "x.go", StartLine: 1}, 5)
	if ctx != nil {
		t.Errorf("expected nil for missing file, got %+v", ctx)
	}
}

func TestReadSourceContext_Binary(t *testing.T) {
	dir := t.TempDir()
	// NUL byte in the window → treat as binary.
	os.WriteFile(filepath.Join(dir, "bin"), []byte("line1\nline\x002\nline3\n"), 0644)
	ctx := readSourceContext(dir, store.Finding{FilePath: "bin", StartLine: 2}, 1)
	if ctx != nil {
		t.Errorf("expected nil for binary content, got %+v", ctx)
	}
}

func TestReadSourceContext_TargetRange(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 1; i <= 20; i++ {
		b.WriteString("line\n")
	}
	os.WriteFile(filepath.Join(dir, "f.py"), []byte(b.String()), 0644)

	f := store.Finding{
		FilePath:  "f.py",
		StartLine: 8,
		EndLine:   sql.NullInt64{Int64: 12, Valid: true},
	}
	ctx := readSourceContext(dir, f, 2)
	if ctx == nil {
		t.Fatal("expected context")
	}
	// ±2 around 8..12 → 6..14
	if ctx.Lines[0].N != 6 || ctx.Lines[len(ctx.Lines)-1].N != 14 {
		t.Errorf("range = %d..%d, want 6..14", ctx.Lines[0].N, ctx.Lines[len(ctx.Lines)-1].N)
	}
	// Lines 8-12 inclusive should be Target.
	for _, l := range ctx.Lines {
		want := l.N >= 8 && l.N <= 12
		if l.Target != want {
			t.Errorf("line %d: Target = %v, want %v", l.N, l.Target, want)
		}
	}
}

// --- SARIF mode ------------------------------------------------------------

func TestBuildReviewFromSARIF(t *testing.T) {
	dir := t.TempDir()
	sarifDoc := `{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "testscan", "version": "1.2.3", "rules": [
				{"id": "r1", "name": "SQLInjection", "shortDescription": {"text": "SQL Injection vulnerability"}, "properties": {"tags": ["CWE-89"]}}
			]}},
			"results": [
				{"ruleId": "r1", "level": "error", "message": {"text": "sql injection"},
				 "locations": [{"physicalLocation": {
				   "artifactLocation": {"uri": "app/db.go"},
				   "region": {"startLine": 10, "endLine": 12, "snippet": {"text": "db.Query(x)"}}
				 }}]},
				{"ruleId": "r1", "level": "warning", "message": {"text": "another"},
				 "locations": [{"physicalLocation": {
				   "artifactLocation": {"uri": "app/auth.go"},
				   "region": {"startLine": 5}
				 }}]}
			]
		}]
	}`
	sarifPath := filepath.Join(dir, "out.sarif")
	if err := os.WriteFile(sarifPath, []byte(sarifDoc), 0644); err != nil {
		t.Fatal(err)
	}

	rd, err := BuildReviewFromSARIF(sarifPath, "", 5)
	if err != nil {
		t.Fatalf("BuildReviewFromSARIF: %v", err)
	}

	if rd.Mode != "sarif" {
		t.Errorf("Mode = %q, want sarif", rd.Mode)
	}
	if rd.Meta.ToolName != "testscan" || rd.Meta.ToolVersion != "1.2.3" {
		t.Errorf("Meta = %+v, want testscan 1.2.3", rd.Meta)
	}
	if rd.Summary != nil {
		t.Error("Summary should be nil in sarif mode")
	}
	if len(rd.Unmatched) != 2 {
		t.Fatalf("got %d findings, want 2", len(rd.Unmatched))
	}

	// Sorted by severity: db.go (error) before auth.go (warning).
	if rd.Unmatched[0].Finding.FilePath != "app/db.go" {
		t.Errorf("first finding = %s, want app/db.go (error sorts before warning)", rd.Unmatched[0].Finding.FilePath)
	}
	if rd.Unmatched[1].Finding.FilePath != "app/auth.go" {
		t.Errorf("second finding = %s, want app/auth.go", rd.Unmatched[1].Finding.FilePath)
	}

	// db.go finding carried a snippet through.
	dbCard := rd.Unmatched[0]
	if !dbCard.Finding.Snippet.Valid || dbCard.Finding.Snippet.String != "db.Query(x)" {
		t.Errorf("snippet = %+v, want db.Query(x)", dbCard.Finding.Snippet)
	}
	if !dbCard.Finding.CWEID.Valid || dbCard.Finding.CWEID.String != "CWE-89" {
		t.Errorf("cwe = %+v, want CWE-89", dbCard.Finding.CWEID)
	}

	// No DB-backed context.
	for _, c := range rd.Unmatched {
		if c.Match != nil || c.Disposition != nil || c.NearMiss != nil || c.TriageCmd != "" {
			t.Errorf("sarif mode should not populate Match/Disposition/NearMiss/TriageCmd: %+v", c)
		}
	}

	// Sequential IDs (1-based, post-sort) so humans can cite "#N".
	if rd.Unmatched[0].Finding.ID != 1 || rd.Unmatched[1].Finding.ID != 2 {
		t.Errorf("sarif IDs = %d,%d, want 1,2", rd.Unmatched[0].Finding.ID, rd.Unmatched[1].Finding.ID)
	}

	// Rule title carried through from reportingDescriptor.name.
	if dbCard.RuleName != "SQLInjection" {
		t.Errorf("RuleName = %q, want SQLInjection", dbCard.RuleName)
	}
}

func TestSevRank(t *testing.T) {
	// Ordering must hold across both SARIF and CVSS vocabularies.
	order := []string{
		"critical",
		"high", "error",
		"medium", "warning",
		"low", "note",
		"info", "none",
		"", "garbage",
	}
	for i := 1; i < len(order); i++ {
		if sevRank(order[i-1]) > sevRank(order[i]) {
			t.Errorf("sevRank(%q)=%d should be <= sevRank(%q)=%d",
				order[i-1], sevRank(order[i-1]), order[i], sevRank(order[i]))
		}
	}
	// Case-insensitive.
	if sevRank("HIGH") != sevRank("high") {
		t.Error("sevRank should be case-insensitive")
	}
	// SARIF/CVSS equivalents share a rank.
	if sevRank("error") != sevRank("high") {
		t.Error("error and high should share a rank")
	}
	if sevRank("warning") != sevRank("medium") {
		t.Error("warning and medium should share a rank")
	}
}

func TestBuildReviewFromSARIF_WithSourceRoot(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "src", "app"), 0755)
	os.WriteFile(filepath.Join(dir, "src", "app", "db.go"),
		[]byte("package app\n\nfunc q() {\n\tdb.Exec(x)\n}\n"), 0644)

	sarifDoc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},"results":[
		{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{
		  "artifactLocation":{"uri":"app/db.go"},"region":{"startLine":4}}}]}
	]}]}`
	sarifPath := filepath.Join(dir, "out.sarif")
	os.WriteFile(sarifPath, []byte(sarifDoc), 0644)

	rd, err := BuildReviewFromSARIF(sarifPath, filepath.Join(dir, "src"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rd.Unmatched) != 1 {
		t.Fatalf("got %d findings", len(rd.Unmatched))
	}
	ctx := rd.Unmatched[0].Context
	if ctx == nil {
		t.Fatal("expected source context from --source-root")
	}
	found := false
	for _, l := range ctx.Lines {
		if l.N == 4 && l.Target && strings.Contains(l.Text, "db.Exec") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected target line 4 with db.Exec, got %+v", ctx.Lines)
	}
}

// --- HTML rendering --------------------------------------------------------

func TestFormatReviewHTML_RunMode(t *testing.T) {
	rd := &ReviewData{
		Mode: "run",
		Meta: ReviewMeta{RunID: 42, Scanner: "semgrep 1.0", Project: "vulnapp"},
		// Summary nil — the template handles that, and constructing
		// analysis.Metrics here pulls in a lot of unrelated fixture setup.
	}

	rd.Unmatched = []FindingCard{
		{
			Finding: store.Finding{
				ID: 55, FilePath: "app/admin.go", StartLine: 15,
				CWEID:    sql.NullString{String: "CWE-213", Valid: true},
				Severity: sql.NullString{String: "high", Valid: true},
				Message:  sql.NullString{String: "Exposure of sensitive info", Valid: true},
				Snippet:  sql.NullString{String: "writeJSON(w, users)", Valid: true},
			},
			NearMiss: &NearMiss{
				Evidence:  store.Evidence{FilePath: "app/models.go", StartLine: 12},
				VulnName:  "user-enum",
				LineDelta: -3,
				CWEDist:   -1,
				Why:       "different bug",
			},
			TriageCmd: `benchmrk triage 42 --set 55 --disposition tp|fp --notes "..."`,
		},
		{
			Finding: store.Finding{
				ID: 56, FilePath: "app/profile.go", StartLine: 27,
				Message: sql.NullString{String: "gob deserialize", Valid: true},
			},
			Disposition: &store.FindingDisposition{
				Disposition: "fp",
				Notes:       sql.NullString{String: "value is trusted", Valid: true},
			},
			TriageCmd: "benchmrk triage 42 --set 56 --disposition tp|fp",
		},
	}
	rd.Matched = []FindingCard{
		{
			Finding: store.Finding{ID: 60, FilePath: "app/auth.go", StartLine: 8},
			Match: &MatchInfo{
				MatchType:  "same_line",
				Confidence: 0.2,
				VulnName:   "weak-jwt",
				Evidence:   store.Evidence{FilePath: "app/auth.go", StartLine: 8},
			},
		},
	}
	rd.Unsatisfied = []VulnCard{
		{
			Vuln: store.Vulnerability{Name: "ssrf-webhook", Criticality: "must"},
			CWEs: []string{"CWE-918"},
			Evidence: []store.Evidence{
				{FilePath: "app/webhook.go", StartLine: 33, Role: "sink", Category: "ssrf"},
			},
		},
	}

	var buf bytes.Buffer
	if err := FormatReviewHTML(rd, &buf); err != nil {
		t.Fatalf("FormatReviewHTML: %v", err)
	}
	out := buf.String()

	checks := []string{
		"run 42",
		"semgrep 1.0",
		"app/admin.go:15",
		"CWE-213",
		"Exposure of sensitive info",
		"writeJSON(w, users)", // snippet fallback (no Context)
		"Near-miss",
		"user-enum",
		"different bug",
		"benchmrk triage 42 --set 55",
		"app/profile.go:27",
		"Disposition:", "fp", "value is trusted", // disposition block
		"Matched findings (1)",
		"same_line", "20%", "weak-jwt",
		"Unsatisfied vulnerabilities (1)",
		"ssrf-webhook", "must", "CWE-918",
		"app/webhook.go:33",
		"No finding in any evidence file", // NearestFinding nil
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("output missing %q", c)
		}
	}
}

func TestFormatReviewHTML_SarifMode(t *testing.T) {
	rd := &ReviewData{
		Mode: "sarif",
		Meta: ReviewMeta{ToolName: "codeql", ToolVersion: "2.0"},
		Unmatched: []FindingCard{
			{
				Finding: store.Finding{
					ID: 1, FilePath: "x.go", StartLine: 1,
					Message: sql.NullString{String: "hello", Valid: true},
				},
				RuleName: "Unchecked sink",
			},
		},
	}
	var buf bytes.Buffer
	if err := FormatReviewHTML(rd, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "SARIF Review") || !strings.Contains(out, "codeql") {
		t.Error("missing sarif header")
	}
	// No FP? badge in sarif mode.
	if strings.Contains(out, ">FP?<") {
		t.Error("sarif mode should not show FP? badge")
	}
	// No filter controls in sarif mode.
	if strings.Contains(out, `id="f-disp"`) {
		t.Error("sarif mode should not render filter controls")
	}
	// Title and sequence ID both rendered.
	if !strings.Contains(out, "Unchecked sink") {
		t.Error("sarif mode should render RuleName as card title")
	}
	if !strings.Contains(out, "#1") {
		t.Error("sarif mode should render sequential finding ID as #N")
	}
}

func TestFormatReviewHTML_Escaping(t *testing.T) {
	rd := &ReviewData{
		Mode: "sarif",
		Unmatched: []FindingCard{
			{Finding: store.Finding{
				FilePath: "x.go", StartLine: 1,
				Message: sql.NullString{String: "<script>alert(1)</script>", Valid: true},
			}},
		},
	}
	var buf bytes.Buffer
	if err := FormatReviewHTML(rd, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("message was not HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("escaped message not found")
	}
}

func TestRenderMsg(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{
			"call `db.Query(x)` with user input",
			"call <code>db.Query(x)</code> with user input",
		},
		{
			// Escape-then-wrap: a backtick span containing HTML must not
			// leak a live tag.
			"found `<img onerror=x>` in template",
			"found <code>&lt;img onerror=x&gt;</code> in template",
		},
		{
			// Stray backtick → left alone. Non-greedy + no-newline means
			// an odd count doesn't eat the rest of the message.
			"uses ` as a prompt char",
			"uses ` as a prompt char",
		},
		{
			"para one\n\npara two",
			"para one<br><br>para two",
		},
		{
			// Backtick spanning a newline isn't a span.
			"a `multi\nline` thing",
			"a `multi\nline` thing",
		},
	}
	for _, tc := range cases {
		if got := string(renderMsg(tc.in)); got != tc.want {
			t.Errorf("renderMsg(%q)\n  got:  %q\n  want: %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatReviewHTML_CrossRun(t *testing.T) {
	rd := &ReviewData{
		Mode:     "run",
		CrossRun: true,
		Meta:     ReviewMeta{RunID: 3},
		Unmatched: []FindingCard{
			{
				Finding: store.Finding{ID: 1, FilePath: "a.go", StartLine: 1},
				CrossRun: []CrossRunHit{
					{RunID: 5, Scanner: "opus", Iteration: 2, Matched: true},
				},
				TriageCmd: "x",
			},
			{
				Finding:   store.Finding{ID: 2, FilePath: "b.go", StartLine: 1},
				TriageCmd: "x",
				// CrossRun empty — should say "only this run"
			},
		},
	}
	var buf bytes.Buffer
	if err := FormatReviewHTML(rd, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Also flagged by:") || !strings.Contains(out, "opus") || !strings.Contains(out, "it2 (run 5)") {
		t.Error("missing cross-run hit")
	}
	if !strings.Contains(out, "Only this run") {
		t.Error("missing 'only this run' for empty cross-run slice")
	}
}

// --- helpers ---------------------------------------------------------------

func TestCritRank(t *testing.T) {
	if !(critRank("must") < critRank("should") && critRank("should") < critRank("may")) {
		t.Error("must < should < may ordering broken")
	}
}

func TestSarifToStoreFinding(t *testing.T) {
	f := sarifToStoreFinding(sarif.Finding{
		RuleID: "r1", FilePath: "app.go", StartLine: 10, EndLine: 15,
		CWE: "CWE-89", Severity: "high", Message: "msg", Snippet: "snip",
	})
	if f.FilePath != "app.go" || f.StartLine != 10 {
		t.Errorf("location: got %s:%d", f.FilePath, f.StartLine)
	}
	if !f.EndLine.Valid || f.EndLine.Int64 != 15 {
		t.Errorf("EndLine: %+v", f.EndLine)
	}
	if !f.CWEID.Valid || f.CWEID.String != "CWE-89" {
		t.Errorf("CWE: %+v", f.CWEID)
	}
	if !f.Snippet.Valid || f.Snippet.String != "snip" {
		t.Errorf("Snippet: %+v", f.Snippet)
	}

	// Empty fields → invalid sql.NullString.
	f2 := sarifToStoreFinding(sarif.Finding{FilePath: "x", StartLine: 1})
	if f2.RuleID.Valid || f2.CWEID.Valid || f2.Message.Valid || f2.EndLine.Valid {
		t.Errorf("empty fields should be invalid: %+v", f2)
	}
}
