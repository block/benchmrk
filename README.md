# benchmrk

A harness for measuring whether static analysis security tools actually find the bugs.

Ships as a single Go binary CLI. See **[SKILLS.md](SKILLS.md)** for structured workflows usable by AI agents.

---

## The problem

You have a SAST tool in CI. It reports things. Some of those things are real vulnerabilities; some are noise. You don't know the ratio, because you've never measured it.

Maybe you're considering a second tool. The vendor says it's better. Better at what? You can run both on the same code and get two lists of findings, but comparing lists by eye tells you who's *louder*, not who's *right*.

What you actually want to know:

- If a known vulnerability exists at `src/auth.py:47`, does the tool find it?
- When the tool reports something, how often is it real?
- Does tool A catch the critical bugs tool B misses, or just more of the same low-severity stuff?
- If you re-run the tool tomorrow, do you get the same answer?

These are measurable questions. benchmrk measures them.

## How it works

You give it two things:

1. **A codebase** — any repository. Could be [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), [WebGoat](https://github.com/WebGoat/WebGoat), the [OWASP Benchmark](https://owasp.org/www-project-benchmark/), or your own code.

2. **Ground truth** — a list of vulnerabilities you know are in that codebase, with file locations and CWE IDs. You write this once. It's the answer key.

> **A caveat on public benchmark corpora and AI-based scanners**
>
> Juice Shop, WebGoat, and OWASP Benchmark are in the training data of
> every large language model. Their source, their solutions, and
> hundreds of blog posts walking through every challenge. An LLM-based
> scanner that "finds" the SQLi at `routes/login.ts:34` may be
> recalling a tutorial, not analyzing code. It will look brilliant on
> Juice Shop and then miss the same pattern in your internal codebase
> — because the pattern was never what it learned.
>
> The same contamination doesn't affect traditional pattern-matching
> tools (semgrep rules, CodeQL queries). Those find what their rules
> describe, regardless of whether the target is famous.
>
> If you're benchmarking an AI-backed scanner, prefer corpora the
> model hasn't seen: a private codebase, a synthetic project with
> freshly-written bugs, or a public project released after the model's
> training cutoff. The public benchmarks are still fine for the setup
> walkthroughs in `examples/` — learn the tool there, measure
> elsewhere.

Then you run scanners. benchmrk invokes them (Docker, local executable, or you run them yourself and import the SARIF), matches what they found against the answer key, and tells you the score.

```
                                                 ┌─────────────┐
                                                 │ ground truth│
                                                 │ (you write) │
                                                 └──────┬──────┘
                                                        │
┌─────────┐    ┌───────────┐    ┌──────────────┐        ▼
│ scanner │───▶│  SARIF    │───▶│   matcher    │    ┌───────────┐
│  runs   │    │  output   │    │ (file, line, │───▶│  metrics  │
└─────────┘    └───────────┘    │  CWE tree)   │    │ TP/FP/FN  │
                                └──────────────┘    │ P/R/F1    │
                                                    └───────────┘
```

The matcher is the interesting part — see [How matching works](#how-matching-works).

---

## Quick start

```bash
# Build
go build -o bin/benchmrk ./cmd/benchmrk
./bin/benchmrk migrate

# Add a project
git clone https://github.com/juice-shop/juice-shop /tmp/juice-shop
./bin/benchmrk corpus add juice-shop --source /tmp/juice-shop

# Import ground truth (see examples/ for the format)
./bin/benchmrk annotate import juice-shop --file examples/juice-shop-vulns.json

# Register a scanner — here, semgrep running locally
./bin/benchmrk scanner register semgrep \
  --version 1.60.0 \
  --mode local \
  --executable ./examples/wrappers/semgrep.sh \
  --output-format sarif

# Scan and score
./bin/benchmrk scan semgrep juice-shop
./bin/benchmrk analyze 1
```

For a full walkthrough, see **[examples/README.md](examples/README.md)**.

---

## Understanding the numbers

This is the part that matters. If you don't understand what the metrics mean, the tool is useless to you.

### The confusion matrix

Every scanner finding, and every ground-truth vulnerability, ends up in exactly one box:

|                              | **Scanner reported it** | **Scanner didn't report it** |
|------------------------------|:-----------------------:|:----------------------------:|
| **It's a real vulnerability** | **TP** (true positive)  | **FN** (false negative)      |
| **It's not a vulnerability**  | **FP** (false positive) | **TN** (true negative)       |

- **TP** — the tool found a real bug. Good.
- **FP** — the tool cried wolf. Every one of these costs a human's time to dismiss.
- **FN** — a real bug the tool missed. This is what gets you breached.
- **TN** — the tool correctly stayed quiet about something that looks suspicious but isn't. You only get credit for these if you annotated the known-not-a-bug locations.

### Derived metrics

**Precision** = TP / (TP + FP)
*"When the tool speaks, how often is it right?"*
Low precision means your developers learn to ignore the tool.

**Recall** = TP / (TP + FN)
*"Of the real bugs, how many did the tool catch?"*
Low recall means you're shipping vulnerabilities the tool could have stopped.

**F1** = 2 × (Precision × Recall) / (Precision + Recall)
The harmonic mean. A single number when you need one. Penalizes imbalance — a tool at precision 0.99 / recall 0.01 scores F1 ≈ 0.02, not 0.50.

**Accuracy** = (TP + TN) / (TP + FP + FN + TN)
Less useful than it sounds. If 95% of your annotations are `valid`, a tool that finds nothing scores 0% accuracy — but a tool that reports everything also scores badly. Use F1.

### Tier recall: the number that actually matters

Overall recall treats every miss as equally bad. It isn't. Missing the `alg:none` JWT bypass is not the same as missing a verbose error message.

benchmrk lets you tag each ground-truth vulnerability with a **criticality tier**:

| Tier   | Meaning                                                                                  |
|--------|------------------------------------------------------------------------------------------|
| `must`   | Any competent tool should find this. Missing it is a defect in the *tool*.             |
| `should` | Reasonable to expect. Missing it is a recall gap, but not disqualifying.               |
| `may`    | Defensible either way. A thorough tool finds it; a selective tool doesn't. Both fine.  |

`compare` then shows recall per tier:

```
METRIC             semgrep-audit   semgrep-owasp   codeql-extended   BEST
Recall             0.5806          0.6452          0.5484            semgrep-owasp
  Recall (must)    1.0000          1.0000          1.0000            semgrep-audit
  Recall (should)  0.5714          0.6071          0.5357            semgrep-owasp
  Recall (may)     0.0000          1.0000          0.0000            semgrep-owasp
```

All three configs caught everything critical. The headline 0.58-vs-0.65 gap is entirely `should`-tier. That's a very different story from "tool B is 12% better."

### Variance: is the difference real?

If you run the same tool twice and get F1 = 0.80 one time and 0.76 the other, a comparison showing tool A at 0.78 vs tool B at 0.80 means nothing.

Set `--iterations 3` (or more) when creating an experiment. `compare` will show `mean ± σ` and flag the winner when confidence intervals overlap:

```
F1    0.7826 ±0.0120    0.8000 ±0.0340    semgrep-owasp (within σ)
```

`(within σ)` means the intervals overlap — don't trust the ranking. Run more iterations or accept that the tools are tied.

### Consensus: is your ground truth reliable?

If one person wrote all your annotations, every metric is measured against that person's judgment. Maybe they were wrong about one.

Multiple people can annotate the same vulnerability. `compare --min-consensus 2` filters to vulnerabilities where at least two annotators agreed it exists, then recomputes. If your F1 moves a lot, your ranking was riding on contested calls.

### Scorer pinning: are the numbers comparable?

Every scored run is stamped with:

- **`matcher_version`** — bumped when benchmrk's matching logic changes
- **`annotation_hash`** — digest of the ground truth at scoring time

`compare` warns when you're comparing runs with different stamps:

```
  ⚠ matcher version differs across runs: 2→runs[1], 3→runs[2 4]
  → numbers below are not directly comparable. Run:  benchmrk rescore <project>
```

`rescore` clears the derived `finding_matches` rows and re-runs the matcher against whatever the project's ground truth is *now*, re-stamping every run with the current hash. Findings stay; only the derived matches are recomputed. It shows the hash spread and asks before touching anything (or pass `--yes`). It refuses if the project has zero annotations, since rescoring against nothing would turn every former TP into an FP.

---

## How matching works

A scanner finding is a (file, line, CWE) tuple. So is a ground-truth entry. Whether they match is harder than it sounds.

**The file and line might not agree.** The scanner points at the sink; the annotator pointed at the source. Or the scanner reports a range and the annotation is a single line inside it.

**The CWE definitely won't agree.** The same SQL-in-a-query bug is CWE-89 (SQL Injection), CWE-943 (Improper Neutralization in Data Query Logic), or CWE-20 (Improper Input Validation) depending on who's classifying. None of these are *wrong*.

benchmrk handles both:

### Location matching

Tiered, from strongest to weakest:

| Tier       | Condition                                                    | Confidence |
|------------|--------------------------------------------------------------|------------|
| `exact`    | Overlapping line ranges, identical CWE                       | 1.00       |
| `hierarchy`| Overlapping line ranges, CWE related in the MITRE tree       | 0.75–0.95  |
| `fuzzy`    | Within 5 lines, CWE related                                  | 0.50–0.90  |
| `category` | Within 20 lines, CWE related                                 | 0.30–0.50  |
| `same_line`| Overlapping lines, CWE unrelated (last-resort fallback)      | 0.20       |

Each finding gets its single best match via greedy assignment. Ties break deterministically (smallest start-line gap, then lowest ID) so re-scoring gives the same result.

### CWE matching

Ground-truth entries carry a **set** of acceptable CWEs, not one. If the annotator says `{CWE-639, CWE-862, CWE-863}` (all flavors of broken access control), a finding reporting any of them is an exact CWE match.

For CWEs outside the declared set, benchmrk walks the [MITRE CWE hierarchy](https://cwe.mitre.org/) (generated from the official XML catalog):

- **Parent/child** — CWE-564 (Hibernate SQL Injection) is a child of CWE-89. One hop, high confidence.
- **Shared ancestor** — CWE-639 and CWE-862 both descend from CWE-285 (Improper Authorization). Two hops.
- **Shared MITRE category** — MITRE's own cross-cutting groupings (OWASP Top 10 slices, etc.).
- **Curated pairs** — a small hand-maintained list for relationships the tree doesn't encode: CWE-915 (mass assignment) *causes* CWE-269 (privilege escalation) when the assignable field is `role`, but MITRE files them under different pillars.

The tree data is generated from MITRE's catalog and committed as Go source. Updating to a new CWE release: `CWE_XML=/path/to/cwec_latest.xml.zip go generate ./internal/analysis/cwe/`.

---

## The ground-truth format

One vulnerability, many locations, many acceptable CWEs:

```json
{
  "vulnerabilities": [
    {
      "name": "order-idor",
      "description": "Order endpoints fetch by ID with no ownership check",
      "criticality": "must",
      "status": "valid",
      "cwes": ["CWE-639", "CWE-862", "CWE-863"],
      "annotated_by": ["alice", "bob"],
      "evidence": [
        {"file": "routes/order.js", "line": 42, "role": "sink",
         "category": "broken-access-control", "severity": "critical"},
        {"file": "routes/order.js", "line": 88, "end": 94, "role": "sink",
         "category": "broken-access-control", "severity": "high"},
        {"file": "routes/order.js", "line": 140, "role": "sink",
         "category": "broken-access-control", "severity": "high"}
      ]
    }
  ]
}
```

Key points:

- **One finding matching any `evidence` location satisfies the whole vulnerability.** Three IDOR endpoints, one scanner hit → one TP, not three. You're measuring "did the tool find *this bug*", not "did it enumerate every symptom."
- **`cwes` is a set.** Put every CWE a reasonable scanner might report. The hierarchy walker covers ones you don't anticipate.
- **`criticality`** drives the tier recall rows. Default is `should`.
- **`status: invalid`** marks known false-positive bait — code that *looks* vulnerable but isn't. A tool that stays quiet scores a TN; one that reports it scores an FP. This is how you measure precision without running the tool on the whole internet.
- **`annotated_by`** is the consensus mechanism. More names = higher consensus = more trustworthy ground truth.

The legacy flat-array format still imports (one annotation → one single-evidence vulnerability). See [examples/](examples/) for both.

---

## Where it excels

### Ruleset A/B testing

Register the same scanner with different configs; compare:

```bash
./bin/benchmrk scanner register semgrep-audit --mode local \
  --executable ./wrappers/semgrep.sh \
  --config '{"env": {"SEMGREP_RULES": "p/security-audit"}}'

./bin/benchmrk scanner register semgrep-owasp --mode local \
  --executable ./wrappers/semgrep.sh \
  --config '{"env": {"SEMGREP_RULES": "p/owasp-top-ten"}}'

./bin/benchmrk compare semgrep-audit semgrep-owasp -p juice-shop
```

The wrapper script reads `SEMGREP_RULES` from its environment — one script, N configs.

### Regression gating

You changed a scanner config. Did it get worse?

```bash
./bin/benchmrk scan semgrep-v2 juice-shop
./bin/benchmrk compare semgrep-v1 semgrep-v2 -p juice-shop
```

If `Recall (must)` dropped, you have a problem. Gate on that, not on overall F1.

### Complement analysis: do I need both tools?

The headline F1 tells you which tool is better. It doesn't tell you if running *both* catches more. `--coverage` does:

```bash
./bin/benchmrk compare semgrep codeql horusec -p juice-shop --coverage
```

```
COVERAGE OVERLAP  (valid vulnerabilities only)

  Union recall:       0.7419   (best single: 0.6452, semgrep)
  → running all 3 scanners gains +0.0967 recall over the best one alone
  Union FP ceiling:   ≤7       (sum of per-scanner FP; real overlap unknown)

  Caught by all      18   [must:3 should:14 may:1]
  Caught by none      8   [must:0 should:6 may:2]   ← blind spots regardless of which you pick

MARGINAL CONTRIBUTION  (dropping this scanner loses these — nobody else catches them)
  semgrep   2   [must:1 should:1]   jwt-alg-none, csrf-token-missing
  codeql    1   [should:1]          mass-assignment-role
  horusec      0                       ← redundant given the others
```

Three things fall out immediately: horusec adds nothing the other two don't already find; dropping semgrep loses a `must`-tier bug; the 8 blind spots are `should`/`may` only, so the suite isn't missing anything critical.

### Coverage gap analysis

A vulnerability was disclosed in a library you use. Would your scanner have caught it?

Write one ground-truth entry for it. Import. Scan. Look at whether that vulnerability is TP or FN. This is a one-vuln benchmark, but it answers the question you actually have.

### Triage feedback loop

Your scanner reported 40 things. You don't know which are real.

```bash
./bin/benchmrk review run <run-id> -o review.html && open review.html
```

One card per finding: the full scanner message, ±5 lines of source from the project checkout, and — for unmatched findings — the nearest ground-truth evidence plus a one-liner on why it didn't match ("13 lines away, same CWE — outside fuzzy range; check if the scanner pointed at a different sink"). Each card has a prefilled `triage --set` command; click to copy, add notes, paste.

```bash
./bin/benchmrk triage <run-id> --set 12 --disposition tp --notes "verified"
./bin/benchmrk triage <run-id> --set 15 --disposition fp --notes "param is a server-side constant"
./bin/benchmrk triage <run-id> --promote --criticality must        # tp → valid, fp → invalid decoy
```

Both directions feed the benchmark: `tp` becomes a new thing future scanners should find; `fp` becomes a decoy future scanners should stay quiet about. If the `tp` is another instance of a bug already in your ground truth, `--attach-to <vuln-name>` adds it as an evidence row instead of a fresh entry.

`review` also works standalone — `benchmrk review sarif results.sarif --source-root ./code` renders any SARIF file without a DB, for a quick look at CI output before import.

---

## CLI reference

| Command | Description |
|---|---|
| `benchmrk migrate` | Run database migrations |
| **Corpus** | |
| `benchmrk corpus add <name> --source <path> [--language <lang>] [--commit <sha>]` | Add a project |
| `benchmrk corpus list` / `show <name>` / `remove <name>` | Manage projects |
| **Ground truth** | |
| `benchmrk annotate import <project> --file <json> [--replace]` | Bulk import (both formats) |
| `benchmrk annotate list <project>` | List ground truth |
| `benchmrk annotate export <project>` | Export as JSON |
| `benchmrk annotate history <project>` | Show import history with hashes |
| `benchmrk annotate diff <hash-a> <hash-b>` | Explain what changed between two annotation sets |
| `benchmrk annotate add <project> --file <f> --line <n> --cwe <id> --category <c> --severity <s>` | Add one entry (compat path) |
| `benchmrk annotate update <id> [flags]` / `delete <id>` | Edit or remove a single entry |
| `benchmrk annotate groups <project>` | List vulnerabilities with multiple evidence rows (legacy view) |
| **Scanners** | |
| `benchmrk scanner register <name> -V <ver> -m local -e <script>` | Register a local scanner |
| `benchmrk scanner register <name> -V <ver> -i <image>` | Register a Docker scanner |
| `benchmrk scanner build <name>` | Build from `scanners/<name>/Dockerfile` |
| `benchmrk scanner list` / `remove <name>` | Manage scanners |
| `benchmrk scan <scanner> <project> [--timeout <min>]` | One-off scan |
| `benchmrk import <scanner> <project> <sarif-file> [--format <f>] [--experiment <id> --iteration <n>] [--output-dir <dir>]` | Import pre-run output |
| **Experiments** | |
| `benchmrk experiment create <name> -s <ids> -p <ids> -i <n> [-d <desc>]` | Create (iterations ≥ 3 recommended) |
| `benchmrk experiment run <id> [--concurrency <n>] [--reuse] [--output-dir <dir>]` | Execute all runs |
| `benchmrk experiment resume <id> [--reuse] [--output-dir <dir>]` | Retry failed/pending |
| `benchmrk experiment status <id>` / `results <id>` | View progress |
| **Analysis** | |
| `benchmrk analyze <run-id> [--detail]` | Score one run |
| `benchmrk analyze experiment <id>` | Aggregate across an experiment |
| `benchmrk compare <a> <b> [c...] -p <project> [--min-consensus <n>] [--coverage]` | Compare scanners. `--coverage` shows which vulns each uniquely catches. |
| `benchmrk rescore <project> [--yes] [--clear-only]` | Re-match all runs against current ground truth |
| `benchmrk rescore --run <id>` | Re-match one run |
| **Triage** | |
| `benchmrk triage <run-id>` | List unmatched findings |
| `benchmrk triage <run-id> --set <id> --disposition tp\|fp\|needs_review --notes "..."` | Classify |
| `benchmrk triage <run-id> --promote [--criticality must\|should\|may] [--attach-to <vuln>]` | tp → valid entries, fp → invalid decoys. Idempotent. |
| **Reports** | |
| `benchmrk report <exp-id> --format md\|json\|csv\|html\|sarif` | Generate metric-centric report |
| `benchmrk review run <run-id> [-o out.html] [--cross-run] [--context-lines <n>]` | Finding-centric triage page — one card per finding with rule title, source context, near-miss hints, prefilled triage commands |
| `benchmrk review sarif <file> [--source-root <path>] [--context-lines <n>]` | Render any SARIF as a review page, no DB required. Each card gets a stable sequential `#N` ID. |
| `benchmrk logs <run-id>` | View scanner output |

## Scanner contract

**Local mode** — your executable receives a **minimal** environment:
- `$PATH`, `$HOME`, `$TMPDIR`, `$LANG` — passed through from benchmrk's own env
- `$TARGET_DIR` = absolute corpus path (also the working directory)
- `$OUTPUT_DIR` = where to write results
- `$SCANNER_NAME`, `$SCANNER_VERSION`, `$TARGET_LANGUAGE`
- Plus any `env` keys from the scanner's `--config` JSON

Nothing else is inherited. If your wrapper needs `HTTPS_PROXY`, `JAVA_HOME`, `SSL_CERT_FILE`, etc., pass them via `--config '{"env": {"JAVA_HOME": "..."}}'`. This keeps cloud credentials and API keys out of scanner processes by default.

Write SARIF 2.1.0 to `$OUTPUT_DIR/results.sarif`. See `examples/wrappers/` for semgrep, bandit, and codeql.

**Docker mode** — container receives `/target` (ro, the code) and `/output` (rw, write `results.sarif` here); `$TARGET_DIR`/`$OUTPUT_DIR` are local-mode only. The scanner-metadata env vars (`$SCANNER_NAME`, `$SCANNER_VERSION`, `$TARGET_LANGUAGE`, plus anything from `--config`'s `env` block) are still passed in. Runs with `--network none` — the scanner reads code from a mount and writes to a mount; it doesn't need network, and a compromised image shouldn't be able to exfiltrate source. If your scanner fetches rules at runtime, bake them into the image instead.

**Neither** — run the scanner yourself however you like, `benchmrk import` the SARIF.

## Architecture

```
cmd/benchmrk/          CLI (Cobra)
internal/
  store/               SQLite, embedded migrations, WAL mode
  corpus/              Project + ground-truth management
  scanner/             Docker + subprocess orchestration
  sarif/               SARIF 2.1.0 parser
  normalise/           Format normalisation (semgrep-json → SARIF)
  analysis/            Matcher, metrics, CWE hierarchy
    cwe/               MITRE tree walker (generated from cwe.mitre.org XML)
  experiment/          Matrix execution with concurrency + resume
  report/              Multi-format output
```

### Data model (simplified)

```
corpus_projects ──< vulnerabilities ──< vuln_evidence
                                   ──< vuln_cwes
                                   ──< vuln_annotators
scanners ──< experiment_scanners >── experiments ──< runs ──< findings
                                                                   │
                                     vuln_evidence >── finding_matches
```

Also present: `finding_dispositions` (triage state), `annotation_sets` (import provenance), `experiment_projects`. Omitted above for readability.

## Development

```bash
make test    # full suite with race detector
make lint    # golangci-lint
make build   # → bin/benchmrk
```

## Tech stack

Go (single binary, no CGO). SQLite via [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite). Cobra CLI. golang-migrate. SARIF 2.1.0 as interchange.

## Future work

* Severity properties for annotations and matching: Allow benchmrk to make commentary on expected issue severity vs. reported severity to isolate over or under-reporting of vulnerability ratings.
* Generalised matchers (decouple from "security tool scanning"): benchmrk could be a harness for comparing any tool that can have annotated output, not restricted to the security domain.

## License

Apache License 2.0. See [LICENSE](./LICENSE) for the full text.
