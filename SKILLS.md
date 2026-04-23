# benchmrk — skill entries for agents

Structured workflows for operating `benchmrk` via CLI. Each entry has a
trigger condition, required inputs, command sequence, and guardrails.

The README covers *why* these commands exist. This file covers *exactly
what to type*.

## Shared preconditions

Run before any workflow:

```bash
# Build if needed
go build -o bin/benchmrk ./cmd/benchmrk

# Schema up to date
./bin/benchmrk migrate

# Orient
./bin/benchmrk corpus list
./bin/benchmrk scanner list
```

All commands below assume `./bin/benchmrk` as the binary path and the
default database location (`~/.benchmrk/benchmrk.db`). Override with
`--db /path/to/benchmrk.db`.

---

## Entry: writing-ground-truth

**Use when:** asked to create, convert, or fix an annotation file. This
is the most judgment-heavy task — the annotation file *is* the answer
key, and every metric is measured against it.

**Inputs:** a codebase, knowledge of its vulnerabilities (from a
security report, CVE, fix PR, or code review).

**Output:** a JSON file in the vulnerability format.

### Format

Top level is an object (the `{` is how benchmrk distinguishes this from
the legacy flat-array format):

```json
{
  "vulnerabilities": [
    {
      "name": "order-idor",
      "description": "Order endpoints fetch by ID without ownership check",
      "criticality": "must",
      "status": "valid",
      "cwes": ["CWE-639", "CWE-862"],
      "annotated_by": ["agent"],
      "evidence": [
        {"file": "routes/order.js", "line": 42, "role": "sink",
         "category": "broken-access-control", "severity": "critical"},
        {"file": "routes/order.js", "line": 88, "end": 94, "role": "sink",
         "category": "broken-access-control", "severity": "high"}
      ]
    },
    {
      "name": "login-query-sqli",
      "description": "Username concatenated into SQL in login handler",
      "criticality": "must",
      "cwes": ["CWE-89"],
      "annotated_by": ["agent"],
      "evidence": [
        {"file": "routes/auth.js", "line": 23, "role": "sink",
         "category": "sql-injection", "severity": "critical"}
      ]
    },
    {
      "name": "escaped-search-not-xss",
      "description": "Looks like reflected XSS but template auto-escapes",
      "status": "invalid",
      "cwes": ["CWE-79"],
      "annotated_by": ["agent"],
      "evidence": [
        {"file": "views/search.ejs", "line": 15, "role": "sink",
         "category": "xss", "severity": "low"}
      ]
    }
  ]
}
```

### Field reference

| Field            | Required | Notes |
|------------------|----------|-------|
| `name`           | yes      | Unique within the file. Short identifier. |
| `description`    | no       | One sentence. Why is this a bug? |
| `criticality`    | no       | `must` / `should` / `may`. Default `should`. |
| `status`         | no       | `valid` / `invalid` / `disputed`. Default `valid`. |
| `cwes`           | no       | Array. Every CWE a reasonable scanner might report. |
| `annotated_by`   | no       | Array of names. `len()` = consensus level. |
| `evidence`       | yes      | Array, min 1. The locations. |
| `evidence[].file`| yes      | Repository-relative path. |
| `evidence[].line`| yes      | Positive integer. |
| `evidence[].end` | no       | End of range. Default = `line`. |
| `evidence[].role`| no       | `sink` / `source` / `helper` / `related`. Default `sink`. |
| `evidence[].category` | yes | Free-form bucket. `sql-injection`, `xss`, `idor`, etc. |
| `evidence[].severity` | yes | `critical` / `high` / `medium` / `low` / `info`. |

### Guardrails

1. **One vulnerability, N locations — not N vulnerabilities.** If the
   same missing-authz bug appears on GET, POST, and DELETE handlers,
   that is one entry with three `evidence` rows. The metric question is
   "did the tool find *this bug*", not "did it enumerate every
   endpoint."

2. **`cwes` is a set — be generous.** If the bug is broken access
   control, list `["CWE-639", "CWE-862", "CWE-863"]`. A scanner
   reporting any of them should score a match. The CWE hierarchy walker
   handles ones you didn't anticipate, but explicit is better.

3. **Assign `criticality` deliberately.**
   - `must`: you would reject a SAST tool that missed this in a demo.
     SQLi in a login form. `alg:none` on a JWT. `eval(request.body)`.
   - `should`: a good tool finds this; a mediocre one might not.
   - `may`: a timing side-channel dominated by a worse flaw on the same
     line. A missing security header on a page with nothing sensitive.
     Defensible either way.

4. **Include `status: invalid` entries.** Code that *looks* vulnerable
   but isn't — parameterized query that superficially resembles
   concatenation, XSS-shaped template that auto-escapes. A tool that
   stays quiet scores TN; one that flags it scores FP. Without these,
   you can't measure precision.

5. **Use repository-relative paths.** `routes/order.js`, not
   `/tmp/juice-shop/routes/order.js`. The matcher normalizes common
   prefixes but don't rely on it.

6. **If converting from the legacy format** (flat array with `group`
   field): each group becomes one vulnerability, members become
   `evidence` rows, distinct CWEs across members become the `cwes`
   array. Ungrouped entries become single-evidence vulnerabilities. The
   legacy import path still works but drops the `group` field with a
   warning.

### Import and verify

```bash
./bin/benchmrk annotate import <project> --file vulns.json --replace
./bin/benchmrk annotate list <project>
./bin/benchmrk annotate history <project>   # shows hash, format, vuln count
```

`--replace` is almost always what you want. Importing without it
**appends**, and if any vuln names in the file already exist the
import will refuse — re-importing the same file twice would double
every vuln, and the matcher's 1-to-1 assignment means the duplicate
copy never matches, silently halving recall. The error lists the
colliding names and tells you to use `--replace`.

Appending without `--replace` is only for the narrow case where the
file contains genuinely new vulns not already in the project (e.g.
adding hand-written entries on top of triage-promoted ones).

---

## Entry: registering-scanners

**Use when:** asked to onboard a SAST tool or add a config variant.

**Inputs:** `scanner_name`, `version`, plus either a wrapper script path
(local mode) or a Docker image (docker mode).

### Local mode

Write a wrapper script that runs the tool and emits SARIF:

```bash
#!/usr/bin/env bash
# examples/wrappers/semgrep.sh
# Receives: TARGET_DIR, OUTPUT_DIR, plus any env from --config
set -euo pipefail
semgrep scan \
  --config "${SEMGREP_RULES:-auto}" \
  --sarif \
  --output "$OUTPUT_DIR/results.sarif" \
  "$TARGET_DIR"
```

Register it:

```bash
./bin/benchmrk scanner register semgrep-audit \
  --version 1.60.0 \
  --mode local \
  --executable ./examples/wrappers/semgrep.sh \
  --config '{"env": {"SEMGREP_RULES": "p/security-audit"}}' \
  --output-format sarif
```

The `env` block in `--config` becomes environment variables for the
wrapper. One wrapper script, N scanner configs.

**The wrapper's environment is minimal** — only `PATH`, `HOME`,
`TMPDIR`, `LANG`, the `TARGET_DIR`/`OUTPUT_DIR` pair, and whatever
`--config` adds. If the wrapper needs `HTTPS_PROXY`, `JAVA_HOME`, a
registry token, etc., put it in the `env` block. Nothing leaks from
benchmrk's own environment by default.

### Docker mode

```bash
# Dockerfile at scanners/<name>/Dockerfile
./bin/benchmrk scanner build semgrep
./bin/benchmrk scanner register semgrep \
  --version 1.60.0 \
  --image benchmrk-scanner-semgrep:latest \
  --output-format sarif
```

Container contract: `/target` (ro), `/output` (rw), same env vars,
write `/output/results.sarif`. **Runs with `--network none`** — if
your image pulls rules at runtime (e.g. `semgrep --config p/...`
hitting the registry), bake them into the image at build time
instead.

### No execution — import only

```bash
# Run the tool yourself, anywhere
semgrep scan --config auto --sarif -o /tmp/out.sarif /path/to/code

# Import the output
./bin/benchmrk import semgrep <project> /tmp/out.sarif
```

### Guardrails

1. **One wrapper, many configs.** Parameterize the wrapper via env;
   register each config as a distinct scanner name
   (`semgrep-audit`, `semgrep-owasp`, `semgrep-custom`).
2. **Output must be SARIF 2.1.0** (or `semgrep-json`, which benchmrk
   normalizes). Most tools have a `--sarif` flag.
3. **Local wrappers must write to `$OUTPUT_DIR/results.sarif`** exactly.
   The filename is not configurable per-run.
4. **If a wrapper suddenly fails after upgrading benchmrk**, check
   whether it was relying on an inherited env var that's no longer
   passed through. Add it to `--config '{"env": {...}}'`.

---

## Entry: one-off-scan

**Use when:** asked to quickly check a tool against a project, or
validate that a scanner registration works.

**Inputs:** `scanner_name`, `project_name`

```bash
./bin/benchmrk scan <scanner> <project> --timeout 30

# Output includes the run ID. Then:
./bin/benchmrk analyze <run_id>           # TP/FP/FN/TN, P/R/F1
./bin/benchmrk analyze <run_id> --detail  # per-vulnerability breakdown
./bin/benchmrk logs <run_id>              # scanner stdout/stderr on failure
```

### Guardrails

1. **Raise `--timeout` for slow tools.** CodeQL database creation can
   take 10+ minutes on a large codebase.
2. **If the scan fails, read the logs first.** Most failures are wrapper
   script bugs, not benchmrk bugs.

---

## Entry: comparative-experiment

**Use when:** asked "which of these tools/configs is better?" This is
the main workflow.

**Inputs:** `experiment_name`, scanner IDs (from `scanner list`),
project IDs (from `corpus list`), iteration count.

```bash
# Create — iterations ≥ 3 so variance is measurable
./bin/benchmrk experiment create ruleset-comparison \
  --scanners 1,2,3 \
  --projects 1 \
  --iterations 3

# Run (output shows experiment ID)
./bin/benchmrk experiment run <exp_id> --concurrency 2

# Monitor
./bin/benchmrk experiment status <exp_id>

# Retry failures
./bin/benchmrk experiment resume <exp_id>

# Compare
./bin/benchmrk compare <scanner-a> <scanner-b> <scanner-c> -p <project>
```

### Reading compare output

```
METRIC             semgrep-audit   semgrep-owasp   codeql   BEST
TP                 18              20              17       semgrep-owasp
FP                 1               4               0        codeql
FN                 13              11              14       semgrep-owasp
TN                 10              10              10       semgrep-audit
Precision          0.9474          0.8333          1.0000   codeql
Recall             0.5806          0.6452          0.5484   semgrep-owasp
  Recall (must)    1.0000          1.0000          1.0000   semgrep-audit
  Recall (should)  0.5714          0.6071          0.5357   semgrep-owasp
  Recall (may)     0.0000          1.0000          0.0000   semgrep-owasp
F1                 0.7200 ±0.0120  0.7273 ±0.0340  0.7083   semgrep-owasp (within σ)
```

Interpretation priority:
1. **`Recall (must)`** — if any tool is below 1.0 here, that's the
   headline. Report which `must`-tier vulns it missed.
2. **`(within σ)` flags** — when present, the ranking on that row is
   not statistically meaningful. Say so.
3. **Scorer warnings** (`⚠ matcher version differs` / `⚠ annotation set
   differs`) — the comparison is not valid. Run `benchmrk rescore
   <project>` and re-run compare.
4. **Then** precision vs recall tradeoff, F1, etc.

### Guardrails

1. **iterations < 2 means no variance data.** The ±σ disappears and
   `(within σ)` can't fire. Single-iteration results are a smoke test,
   not a measurement.
2. **The first scanner listed is the baseline** for delta calculations.
   Order matters for presentation, not scoring.
3. **`--min-consensus N`** re-scores with only high-consensus vulns:
   ```bash
   ./bin/benchmrk compare a b c -p proj --min-consensus 2
   ```
   If the ranking changes, the original was sensitive to contested
   annotations. Report both.
4. **`--coverage`** answers "do I need all these tools, or is one
   redundant?" Shows per-scanner marginal contribution (vulns only
   that scanner catches), union recall vs best-single, and blind
   spots nobody catches. The decision rule:
   - A scanner with **empty marginal** is redundant given the others.
     Drop it.
   - A scanner with **must-tier marginal** is load-bearing. Keep it.
   - If **union recall ≈ best single**, one tool dominates. Find
     which (the one with non-empty marginals) and drop the rest.
   ```bash
   ./bin/benchmrk compare a b c -p proj --coverage
   ```

---

## Entry: triaging-findings

**Use when:** a scanner reported things not in the ground truth, and
you need to decide if they're real.

**Inputs:** `run_id`

### Review page

Generate a self-contained HTML page with one card per finding —
everything you need to make the tp/fp call without bouncing between
terminal and editor. Unmatched findings first; each card shows the full
scanner message, ±5 lines of source, the nearest evidence (and why it
didn't match), and a prefilled `triage --set` command.

```bash
./bin/benchmrk review run <run_id> -o /tmp/review.html
open /tmp/review.html

# See which sibling runs flagged the same locations
./bin/benchmrk review run <run_id> --cross-run -o /tmp/review.html

# No DB — render any SARIF file
./bin/benchmrk review sarif results.sarif --source-root /path/to/code -o /tmp/review.html
```

### Disposition

```bash
./bin/benchmrk triage <run_id>   # list unmatched findings

./bin/benchmrk triage <run_id> --set <id> --disposition tp --notes "verified: input reaches query at line 47"
./bin/benchmrk triage <run_id> --set <id> --disposition fp --notes "value is a server constant, not user input"
./bin/benchmrk triage <run_id> --set <id> --disposition needs_review
```

### Promote

`--promote` writes both kinds of disposition into ground truth:

| Disposition | Becomes | Effect on future runs |
|---|---|---|
| `tp` | `status: valid` vulnerability | Next scanner that finds it scores TP; one that misses it scores FN. |
| `fp` | `status: invalid` vulnerability (a decoy) | Next scanner that flags it scores a matched-FP with your notes attached; one that correctly stays quiet scores a TN it couldn't have scored before. |
| `needs_review` | nothing | Stays in limbo. |

```bash
# Plain promote: tp → new valid vulns (should-tier), fp → new invalid decoys
./bin/benchmrk triage <run_id> --promote

# Set criticality for tp promotions (fp ignores this — decoys aren't tiered)
./bin/benchmrk triage <run_id> --promote --criticality must

# Attach tp findings as evidence on an existing vuln instead of creating new ones.
# The target's CWE set grows to include the finding's CWE. fp ignores --attach-to.
./bin/benchmrk triage <run_id> --promote --attach-to basket-idor
```

**Batching:** `--promote` is idempotent — a finding that already has a
match is skipped. This lets you mix attach and fresh-vuln promotion:

```bash
# Step 1: disposition and attach just the cluster members
./bin/benchmrk triage <run_id> --set 12 --disposition tp --notes "another basket-idor endpoint"
./bin/benchmrk triage <run_id> --set 15 --disposition tp --notes "same"
./bin/benchmrk triage <run_id> --promote --attach-to basket-idor

# Step 2: disposition and promote the rest. 12 and 15 are matched → skipped.
./bin/benchmrk triage <run_id> --set 20 --disposition tp --notes "unrelated new bug"
./bin/benchmrk triage <run_id> --set 21 --disposition fp --notes "test fixture"
./bin/benchmrk triage <run_id> --promote --criticality must
```

Metrics update immediately — each promotion writes a `match_type=manual`
row, so `analyze` reflects the change without clearing `finding_matches`.

### Guardrails

1. **Always include `--notes` with evidence.** "tp" with no explanation
   is useless to the next person. One sentence: what did you check?
   For `fp` this is doubly important — the notes are where "not actually
   exploitable because X" lives, and they land in the decoy's
   description.
2. **Use `--attach-to` when the finding is another instance of a known
   bug.** Six IDOR endpoints are one vulnerability with six evidence
   rows, not six vulnerabilities. Attaching keeps the scoring right.
3. **`needs_review` is not a parking lot.** Come back to it.

---

## Entry: annotation-provenance

**Use when:** asked "why did the numbers change?" between two
benchmark runs.

**Inputs:** two annotation hashes — from `runs.annotation_hash` in the
DB, or from `annotate history`.

```bash
# What annotation sets exist?
./bin/benchmrk annotate history <project>

# Output:
#   HASH              VULNS  FORMAT         GIT SHA       SOURCE                    IMPORTED
#   b61d34b3c8c2a341  31     vulnerability  a1b2c3d4e5f6  corpus/juice-vulns.json   2026-03-15 10:22
#   270e831d38a05a0b  28     vulnerability  9f8e7d6c5b4a  corpus/juice-vulns.json   2026-03-01 14:05

# What changed between them?
./bin/benchmrk annotate diff b61d34b3c8c2a341 270e831d38a05a0b

# Output suggests:
#   git diff 9f8e7d6c5b4a a1b2c3d4e5f6 -- corpus/juice-vulns.json
```

### Guardrails

1. **The hash covers scoring-relevant fields only.** Editing a
   description or adding an annotator doesn't churn it. Adding a CWE,
   changing a line number, or changing criticality does.
2. **benchmrk doesn't snapshot content** — it records provenance. The
   actual diff is in git. `annotate diff` tells you which commits to
   compare.
3. **A run stamped with a hash that has no `annotate history` row** was
   scored before the history table existed. The hash is still valid for
   comparison purposes; you just can't trace it to a file.

---

## Entry: generating-reports

**Use when:** asked to export results for humans or machines.

**Inputs:** `experiment_id`, format(s).

```bash
# Stdout, single format
./bin/benchmrk report <exp_id> --format md

# Multiple formats to a directory
./bin/benchmrk report <exp_id> --format md,json,csv,html --output ./reports/
```

### Guardrails

1. **`json` / `csv`** for downstream processing.
2. **`html`** for stakeholder review — self-contained, no server needed.
3. **`md`** for PR comments and chat.
4. **`sarif`** re-emits the findings in SARIF form for tools that
   consume it.

---

## Entry: re-scoring-after-changes

**Use when:** `compare` warns `⚠ annotation set differs` or `⚠ matcher
version differs`, or you know the ground truth changed since scoring.

```bash
# Preview + confirm + clear + rematch, all runs on the project
./bin/benchmrk rescore <project>

# Unattended
./bin/benchmrk rescore <project> --yes

# One run only (e.g. a single import you just updated)
./bin/benchmrk rescore --run <id>

# Clear but don't rematch — next compare does it lazily
./bin/benchmrk rescore <project> --clear-only
```

The preview shows the hash spread (which runs are on which annotation
set) and the target hash (what they'll all end up on). Nothing is
touched until you confirm.

### Guardrails

1. **`finding_matches` is derived state.** `rescore` deletes it and
   recomputes from the `findings` and `vulnerabilities` tables, which
   are untouched. No primary data is at risk.
2. **Refuses to run if the project has no annotations.** Rescoring
   against empty ground truth would turn every former TP into an FP
   and erase every FN. Import first.
3. **Skips pending/failed runs** — they have no findings to match. Only
   `status='completed'` runs are touched.
4. **If one run fails mid-batch** (rare — usually means its findings
   were deleted out-of-band), the rest proceed. Re-run `rescore` to
   retry the stragglers.
5. **Use after migrating benchmrk** to a version with a new
   `MatcherVersion`. Old matches were produced by old logic; a hash
   match doesn't save you from a logic mismatch.

---

## Deprecated commands

These still exist for compatibility but shouldn't be used in new
workflows:

| Command | Why deprecated | Use instead |
|---|---|---|
| `annotate group` | Group-write methods error; groups are now multi-evidence vulns | Edit the JSON, use `evidence[]` |
| `annotate ungroup` | Same | Same |
| Legacy annotation JSON (flat array) | Loses the `group` field on import | Vulnerability format (top-level `{}`) |
