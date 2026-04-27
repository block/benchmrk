package report

import (
	"html/template"
	"io"
	"regexp"
	"strings"
)

// backtickSpan matches a single-backtick code span. Non-greedy and
// disallows newlines inside — a multi-line backtick block in a scanner
// message is more likely a stray backtick than intentional markdown.
var backtickSpan = regexp.MustCompile("`([^`\n]+)`")

// renderMsg turns backtick-delimited spans into <code> tags. Scanner
// messages (LLM-based scanners especially) emit markdown-style `ident`
// references; without this they render as literal backticks in a
// proportional font and the embedded paths/identifiers get lost in the
// prose. Everything is escaped first so the only HTML we emit is our own.
func renderMsg(s string) template.HTML {
	esc := template.HTMLEscapeString(s)
	out := backtickSpan.ReplaceAllString(esc, "<code>$1</code>")
	// Scanner messages also use blank lines for paragraphs; turn those
	// into <br><br> so the pre-wrap block doesn't collapse them.
	out = strings.ReplaceAll(out, "\n\n", "<br><br>")
	return template.HTML(out)
}

// FormatReviewHTML writes a self-contained HTML triage page.
func FormatReviewHTML(data *ReviewData, w io.Writer) error {
	funcMap := template.FuncMap{
		"mult":  func(a, b float64) float64 { return a * b },
		"int64": func(i int) int64 { return int64(i) },
		"msg":   renderMsg,
		// dict lets the card sub-template receive {Card, Mode} together —
		// Go templates can only pass one pipeline value to a nested
		// template, so we wrap both in a map.
		"dict": func(pairs ...interface{}) map[string]interface{} {
			m := make(map[string]interface{}, len(pairs)/2)
			for i := 0; i+1 < len(pairs); i += 2 {
				m[pairs[i].(string)] = pairs[i+1]
			}
			return m
		},
	}

	tmpl, err := template.New("review").Funcs(funcMap).Parse(reviewHTMLTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, data)
}

const reviewHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{if eq .Mode "run"}}Review — run {{.Meta.RunID}}{{else}}SARIF Review — {{.Meta.ToolName}}{{end}}</title>
<style>
  :root {
    --bg: #fafafa; --card: #fff; --text: #1a1a1a; --muted: #666;
    --border: #e0e0e0; --accent: #2563eb; --warn: #d97706; --bad: #dc2626;
    --good: #059669; --code-bg: #f5f5f4; --target-bg: #fef3c7;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    max-width: 1100px; margin: 0 auto; padding: 24px 16px 80px;
    line-height: 1.5; font-size: 14px;
  }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 32px 0 12px; text-transform: uppercase;
       letter-spacing: 0.5px; color: var(--muted); }
  header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 8px; }
  .meta-line { color: var(--muted); font-size: 13px; }
  .summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 12px 0 0; font-size: 13px; }
  .summary span { color: var(--muted); }
  .summary strong { color: var(--text); font-variant-numeric: tabular-nums; }

  .filters { position: sticky; top: 0; background: var(--bg); padding: 12px 0;
             z-index: 10; border-bottom: 1px solid var(--border); display: flex;
             gap: 8px; flex-wrap: wrap; align-items: center; font-size: 13px; }
  .filters input, .filters select { font: inherit; padding: 4px 8px;
             border: 1px solid var(--border); border-radius: 4px; }
  .filters label { color: var(--muted); }
  .count { margin-left: auto; color: var(--muted); }

  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    margin: 12px 0; overflow: hidden;
  }
  .card.hidden { display: none; }
  .card-head {
    padding: 10px 14px; display: flex; align-items: baseline; gap: 10px;
    flex-wrap: wrap; border-bottom: 1px solid var(--border);
    font-family: var(--mono); font-size: 12px;
  }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
           font-size: 11px; font-weight: 600; font-family: inherit; }
  .badge.fp  { background: #fef2f2; color: var(--bad); }
  .badge.tp  { background: #f0fdf4; color: var(--good); }
  .badge.low { background: #fffbeb; color: var(--warn); }
  .badge.crit-must   { background: #fef2f2; color: var(--bad); }
  .badge.crit-should { background: #fffbeb; color: var(--warn); }
  .badge.crit-may    { background: #f0f9ff; color: var(--accent); }
  .loc { font-weight: 600; }
  .title { flex-basis: 100%; font-family: -apple-system, BlinkMacSystemFont,
           "Segoe UI", Roboto, sans-serif; font-size: 13px; font-weight: 600;
           color: var(--text); margin-bottom: 2px; }
  .meta { color: var(--muted); }
  .sev-high, .sev-critical, .sev-error { color: var(--bad); }
  .sev-medium, .sev-warning { color: var(--warn); }
  .sev-low, .sev-info, .sev-note { color: var(--muted); }

  .card-body { padding: 12px 14px; }
  .msg { white-space: pre-wrap; word-wrap: break-word; margin: 0 0 12px;
         font-size: 13px; }
  .section-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
                   color: var(--muted); margin: 12px 0 4px; }
  .section-label:first-child { margin-top: 0; }

  .code { background: var(--code-bg); border-radius: 6px; overflow-x: auto;
          font-family: var(--mono); font-size: 12px; }
  .code-line { display: flex; white-space: pre; }
  .code-line.target { background: var(--target-bg); }
  .ln { flex: 0 0 auto; width: 4ch; padding: 1px 8px; text-align: right;
        color: var(--muted); user-select: none; border-right: 1px solid var(--border); }
  .code-line.target .ln { color: var(--warn); font-weight: 600; }
  .lt { flex: 1; padding: 1px 10px; }
  .snippet-fallback { background: var(--code-bg); border-radius: 6px; padding: 8px 10px;
                      font-family: var(--mono); font-size: 12px; white-space: pre-wrap; }
  code { font-family: var(--mono); font-size: 0.92em; background: rgba(0,0,0,0.06);
         padding: 1px 5px; border-radius: 3px; }

  .nearmiss, .match, .disp, .crossrun {
    margin: 12px 0 0; padding: 8px 10px; border-radius: 6px; font-size: 12px;
  }
  .nearmiss { background: #fffbeb; border-left: 3px solid var(--warn); }
  .nearmiss.none { background: #f0fdf4; border-left-color: var(--good); }
  .match { background: #f0f9ff; border-left: 3px solid var(--accent); }
  .disp  { background: #faf5ff; border-left: 3px solid #9333ea; }
  .crossrun { background: #f8fafc; border-left: 3px solid var(--muted); }
  .crossrun ul { margin: 4px 0 0; padding-left: 18px; }

  .cmd { margin: 12px 0 0; padding: 8px 10px; background: #1a1a1a; color: #d4d4d4;
         font-family: var(--mono); font-size: 12px; border-radius: 6px;
         overflow-x: auto; white-space: pre; cursor: pointer; position: relative; }
  .cmd:hover::after { content: "click to copy"; position: absolute; right: 8px; top: 8px;
                       font-size: 10px; color: #888; }
  .cmd.copied::after { content: "copied!"; color: var(--good); }

  details.section > summary { cursor: pointer; font-size: 16px; font-weight: 600;
    padding: 8px 0; list-style: none; }
  details.section > summary::before { content: "▸ "; color: var(--muted); }
  details.section[open] > summary::before { content: "▾ "; }
  details.section > summary::-webkit-details-marker { display: none; }

  .vuln-ev { font-family: var(--mono); font-size: 12px; color: var(--muted);
             margin: 4px 0 0; padding-left: 12px; }
  .empty { color: var(--muted); font-style: italic; padding: 20px; text-align: center; }
</style>
</head>
<body>

<header>
{{if eq .Mode "run"}}
  <h1>Review — run {{.Meta.RunID}}</h1>
  <div class="meta-line">{{.Meta.Scanner}} · {{.Meta.Project}}</div>
  {{with .Summary}}
  <div class="summary">
    <span>TP <strong>{{.TP}}</strong></span>
    <span>FP <strong>{{.FP}}</strong></span>
    <span>FN <strong>{{.FN}}</strong></span>
    <span>Precision <strong>{{printf "%.1f%%" (mult .Precision 100)}}</strong></span>
    <span>Recall <strong>{{printf "%.1f%%" (mult .Recall 100)}}</strong></span>
    <span>F1 <strong>{{printf "%.1f%%" (mult .F1 100)}}</strong></span>
  </div>
  {{end}}
{{else}}
  <h1>SARIF Review</h1>
  <div class="meta-line">
    {{if .Meta.ToolName}}{{.Meta.ToolName}}{{if .Meta.ToolVersion}} {{.Meta.ToolVersion}}{{end}}{{else}}unknown tool{{end}}
    · {{len .Unmatched}} findings
    {{if .Meta.SourceRoot}}· source: {{.Meta.SourceRoot}}{{end}}
  </div>
{{end}}
  <div class="meta-line" style="margin-top:8px; font-size:11px">
    Generated {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}
  </div>
</header>

{{if eq .Mode "run"}}
<div class="filters">
  <label>disposition <select id="f-disp">
    <option value="">all</option>
    <option value="none">untriaged</option>
    <option value="tp">tp</option>
    <option value="fp">fp</option>
    <option value="needs_review">needs_review</option>
  </select></label>
  <label>file <input type="text" id="f-file" placeholder="filter…" size="20"></label>
  <span class="count" id="count"></span>
</div>
{{end}}

<h2>{{if eq .Mode "run"}}Unmatched findings{{else}}Findings{{end}}
    <span style="color:var(--muted); font-weight:normal">({{len .Unmatched}})</span></h2>
{{if .Unmatched}}
<div id="unmatched-list">
{{range .Unmatched}}{{template "card" dict "Card" . "Mode" $.Mode "CrossRun" $.CrossRun}}{{end}}
</div>
{{else}}
<p class="empty">Nothing to triage.</p>
{{end}}

{{if .Matched}}
<details class="section">
  <summary>Matched findings ({{len .Matched}}) — low confidence first</summary>
  {{range .Matched}}{{template "card" dict "Card" . "Mode" $.Mode "CrossRun" $.CrossRun}}{{end}}
</details>
{{end}}

{{if .Unsatisfied}}
<details class="section" open>
  <summary>Unsatisfied vulnerabilities ({{len .Unsatisfied}}) — the FNs</summary>
  {{range .Unsatisfied}}
  <div class="card">
    <div class="card-head">
      <span class="badge crit-{{.Vuln.Criticality}}">{{.Vuln.Criticality}}</span>
      <span class="loc">{{.Vuln.Name}}</span>
      {{range .CWEs}}<span class="meta">{{.}}</span>{{end}}
    </div>
    <div class="card-body">
      {{if .Vuln.Description.Valid}}<p class="msg">{{msg .Vuln.Description.String}}</p>{{end}}
      <div class="section-label">Evidence locations</div>
      {{range .Evidence}}<div class="vuln-ev"><code>{{.FilePath}}:{{.StartLine}}</code> ({{.Role}}, {{.Category}})</div>{{end}}
      {{if .NearestFinding}}
      <div class="nearmiss">
        ⓘ {{.NearestFinding.Why}} —
        <code>{{.NearestFinding.Finding.FilePath}}:{{.NearestFinding.Finding.StartLine}}</code>{{if .NearestFinding.Finding.CWEID.Valid}} (<code>{{.NearestFinding.Finding.CWEID.String}}</code>){{end}}
      </div>
      {{else}}
      <div class="nearmiss none">✓ No finding in any evidence file — the scanner simply missed this.</div>
      {{end}}
    </div>
  </div>
  {{end}}
</details>
{{end}}

{{define "card"}}
{{$c := .Card}}{{$mode := .Mode}}{{$cross := .CrossRun}}
<div class="card" data-disp="{{if $c.Disposition}}{{$c.Disposition.Disposition}}{{else}}none{{end}}" data-file="{{$c.Finding.FilePath}}">
  <div class="card-head">
    {{if $c.RuleName}}<div class="title">{{$c.RuleName}}</div>{{end}}
    {{if eq $mode "run"}}
      {{if $c.Match}}
        <span class="badge {{if lt $c.Match.Confidence 0.5}}low{{else}}tp{{end}}">{{$c.Match.MatchType}} · {{printf "%.0f%%" (mult $c.Match.Confidence 100)}}</span>
      {{else if $c.Disposition}}
        <span class="badge {{$c.Disposition.Disposition}}">{{$c.Disposition.Disposition}}</span>
      {{else}}
        <span class="badge fp">FP?</span>
      {{end}}
    {{end}}
    <span class="loc">{{$c.Finding.FilePath}}:{{$c.Finding.StartLine}}{{if and $c.Finding.EndLine.Valid (ne $c.Finding.EndLine.Int64 (int64 $c.Finding.StartLine))}}-{{$c.Finding.EndLine.Int64}}{{end}}</span>
    {{if $c.Finding.CWEID.Valid}}<span class="meta">{{$c.Finding.CWEID.String}}</span>{{end}}
    {{if $c.Finding.Severity.Valid}}<span class="meta sev-{{$c.Finding.Severity.String}}">{{$c.Finding.Severity.String}}</span>{{end}}
    {{if $c.Finding.RuleID.Valid}}<span class="meta">{{$c.Finding.RuleID.String}}</span>{{end}}
    {{if $c.Finding.ID}}<span class="meta" style="margin-left:auto">#{{$c.Finding.ID}}</span>{{end}}
  </div>
  <div class="card-body">
    {{if $c.Finding.Message.Valid}}<p class="msg">{{msg $c.Finding.Message.String}}</p>{{end}}

    {{if $c.Context}}
    <div class="section-label">Code context</div>
    <div class="code lang-{{$c.Context.Language}}">
      {{range $c.Context.Lines}}<div class="code-line{{if .Target}} target{{end}}"><span class="ln">{{.N}}</span><span class="lt">{{.Text}}</span></div>{{end}}
    </div>
    {{else if $c.Finding.Snippet.Valid}}
    <div class="section-label">Snippet (from SARIF — source not readable)</div>
    <div class="snippet-fallback">{{$c.Finding.Snippet.String}}</div>
    {{end}}

    {{if $c.Match}}
    <div class="match">
      → matched <strong>{{$c.Match.VulnName}}</strong>
      · <code>{{$c.Match.Evidence.FilePath}}:{{$c.Match.Evidence.StartLine}}</code> · {{$c.Match.MatchType}}
    </div>
    {{end}}

    {{if $c.NearMiss}}
    <div class="nearmiss">
      ⓘ Near-miss: <strong>{{$c.NearMiss.VulnName}}</strong> at <code>{{$c.NearMiss.Evidence.FilePath}}:{{$c.NearMiss.Evidence.StartLine}}</code>
      ({{if ge $c.NearMiss.LineDelta 0}}+{{end}}{{$c.NearMiss.LineDelta}} lines)<br>
      <span class="meta">{{$c.NearMiss.Why}}</span>
    </div>
    {{else if and (eq $mode "run") (not $c.Match)}}
    <div class="nearmiss none">✓ No evidence in this file — not a matching artifact.</div>
    {{end}}

    {{if $c.CrossRun}}
    <div class="crossrun">
      <strong>Also flagged by:</strong>
      <ul>{{range $c.CrossRun}}<li><code>{{.Scanner}}</code> it{{.Iteration}} (run {{.RunID}}){{if .Matched}} — matched{{else}} — unmatched{{end}}</li>{{end}}</ul>
    </div>
    {{else if $cross}}
    <div class="crossrun"><span class="meta">Only this run flagged this location.</span></div>
    {{end}}

    {{if $c.Disposition}}
    <div class="disp">
      Disposition: <strong>{{$c.Disposition.Disposition}}</strong>
      {{if $c.Disposition.Notes.Valid}}— {{$c.Disposition.Notes.String}}{{end}}
    </div>
    {{end}}

    {{if $c.TriageCmd}}<div class="cmd" onclick="copyCmd(this)">$ {{$c.TriageCmd}}</div>{{end}}
  </div>
</div>
{{end}}

<script>
function copyCmd(el) {
  var txt = el.textContent.replace(/^\$ /, '');
  navigator.clipboard.writeText(txt).then(function() {
    el.classList.add('copied');
    setTimeout(function() { el.classList.remove('copied'); }, 1200);
  });
}

(function() {
  var fDisp = document.getElementById('f-disp');
  var fFile = document.getElementById('f-file');
  var count = document.getElementById('count');
  if (!fDisp) return; // sarif mode has no filters

  var cards = document.querySelectorAll('#unmatched-list .card');

  function apply() {
    var disp = fDisp.value;
    var file = fFile.value.toLowerCase();
    var shown = 0;
    cards.forEach(function(c) {
      var ok = true;
      if (disp && c.dataset.disp !== disp) ok = false;
      if (file && c.dataset.file.toLowerCase().indexOf(file) < 0) ok = false;
      c.classList.toggle('hidden', !ok);
      if (ok) shown++;
    });
    count.textContent = shown + ' / ' + cards.length;
  }

  fDisp.addEventListener('change', apply);
  fFile.addEventListener('input', apply);
  apply();
})();
</script>
</body>
</html>`
