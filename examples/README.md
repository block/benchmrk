# Examples

Worked scenarios, from setup to interpretation.

Every example here uses public tools and public datasets. Substitute
your own.

> **If any scanner you're benchmarking uses an LLM under the hood,**
> don't trust results against Juice Shop, WebGoat, or OWASP Benchmark.
> Those codebases and their solutions are in every model's training
> data — you may be measuring memorization, not detection. Run the
> walkthroughs below to learn the tooling, then re-measure against
> code the model hasn't seen. See the README for the full caveat.

## Files

| | |
|---|---|
| `annotations/juice-shop-vulns.json` | Ground truth for OWASP Juice Shop. Shows multi-evidence vulns, CWE sets, criticality tiers, valid and invalid entries. |
| `wrappers/semgrep.sh`   | Local wrapper, parameterized by `SEMGREP_RULES` env var. |
| `wrappers/bandit.sh`    | Local wrapper for Python's bandit. |
| `wrappers/codeql.sh`    | Local wrapper for GitHub CodeQL. Slow; raise `--timeout`. |

---

## Scenario 1: Is my CI scanner any good?

You have semgrep in CI with `--config auto`. You want a number.

```bash
# Setup
go build -o bin/benchmrk ./cmd/benchmrk
./bin/benchmrk migrate

git clone https://github.com/juice-shop/juice-shop /tmp/juice-shop
./bin/benchmrk corpus add juice-shop --source /tmp/juice-shop
./bin/benchmrk annotate import juice-shop --file examples/annotations/juice-shop-vulns.json

./bin/benchmrk scanner register semgrep-auto \
  --version "$(semgrep --version)" \
  --mode local \
  --executable ./examples/wrappers/semgrep.sh \
  --config '{"env": {"SEMGREP_RULES": "auto"}}' \
  --output-format sarif

# Run and score
./bin/benchmrk scan semgrep-auto juice-shop
./bin/benchmrk analyze 1
```

You get a block like:

```
TP: 12    FP: 8    FN: 6    TN: 3
Precision: 0.6000    Recall: 0.6667    F1: 0.6316
```

### What this tells you

- **Precision 0.60** — 40% of what it reports is noise. Your developers
  have probably noticed.
- **Recall 0.67** — it's missing a third of the known bugs. Which
  third? Run with `--detail`:

```bash
./bin/benchmrk analyze 1 --detail
```

Look for `FN` rows. Those are the vulnerabilities your CI would ship.

---

## Scenario 2: Which ruleset should we use?

You want to compare `p/security-audit`, `p/owasp-top-ten`, and
`p/javascript` on the same codebase.

```bash
# One wrapper, three configs
for rules in security-audit owasp-top-ten javascript; do
  ./bin/benchmrk scanner register "semgrep-$rules" \
    --version "$(semgrep --version)" \
    --mode local \
    --executable ./examples/wrappers/semgrep.sh \
    --config "{\"env\": {\"SEMGREP_RULES\": \"p/$rules\"}}" \
    --output-format sarif
done

# Get the IDs
./bin/benchmrk scanner list

# Experiment: 3 iterations so variance is measurable
./bin/benchmrk experiment create ruleset-shootout \
  --scanners 1,2,3 \
  --projects 1 \
  --iterations 3

./bin/benchmrk experiment run 1 --concurrency 3

# Compare
./bin/benchmrk compare semgrep-security-audit semgrep-owasp-top-ten semgrep-javascript \
  -p juice-shop
```

### What to look for

```
METRIC             semgrep-security-audit   semgrep-owasp-top-ten   semgrep-javascript   BEST
Precision          0.9474                   0.8333                  0.5200               semgrep-security-audit
Recall             0.5806                   0.6452                  0.7500               semgrep-javascript
  Recall (must)    1.0000                   1.0000                  1.0000               semgrep-security-audit
  Recall (should)  0.5714                   0.6071                  0.7857               semgrep-javascript
  Recall (may)     0.0000                   1.0000                  0.5000               semgrep-owasp-top-ten
F1                 0.7200 ±0.0120           0.7273 ±0.0340          0.6176 ±0.0850       semgrep-owasp-top-ten (within σ)
```

Reading this top to bottom:

1. **All three hit 1.0 on `Recall (must)`.** None of them misses the
   critical stuff. Good — you can choose on other criteria.
2. **`javascript` has the best overall recall but the worst precision.**
   It finds more, at the cost of noise. Is 48% false positives
   tolerable in your workflow?
3. **F1 shows `(within σ)`** — at 3 iterations, the top two are
   statistically tied. Either run more iterations or accept the tie
   and choose on precision-vs-recall preference.
4. **The `(may)` row is interesting** — `owasp-top-ten` is the only one
   finding the low-priority stuff. If you care, that's a tiebreaker.
   If you don't, it's noise in the overall number.

The answer here isn't "X is best." It's "X is best *for CI gating*"
(high precision) vs "Y is best *for a one-time audit*" (high recall).

---

## Scenario 3: Did our custom rules make things worse?

You added custom semgrep rules. You want to know if you broke anything.

```bash
# Register both configs
./bin/benchmrk scanner register semgrep-baseline \
  --version "$(semgrep --version)" --mode local \
  --executable ./examples/wrappers/semgrep.sh \
  --config '{"env": {"SEMGREP_RULES": "p/security-audit"}}' \
  --output-format sarif

./bin/benchmrk scanner register semgrep-custom \
  --version "$(semgrep --version)" --mode local \
  --executable ./examples/wrappers/semgrep.sh \
  --config '{"env": {"SEMGREP_RULES": "p/security-audit ./our-rules/"}}' \
  --output-format sarif

# Scan both, compare
./bin/benchmrk scan semgrep-baseline juice-shop
./bin/benchmrk scan semgrep-custom juice-shop
./bin/benchmrk compare semgrep-baseline semgrep-custom -p juice-shop
```

### The only number that matters here

```
  Recall (must)    1.0000    0.8571    semgrep-baseline
```

If `Recall (must)` dropped, **stop**. Your custom rules interfered with
detecting something critical. Find out what:

```bash
./bin/benchmrk analyze <custom-run-id> --detail | grep -A1 "FN.*must"
```

If `must` held at 1.0 and only precision changed, the custom rules
added some noise. Annoying, fixable, not a blocker.

---

## Scenario 4: Triaging a noisy scan

semgrep reported 40 things. Only 12 matched your ground truth. What
about the other 28?

```bash
./bin/benchmrk triage <run-id>
```

You get a table of unmatched findings. For each one, look at the code
and decide:

```bash
# This one's real — the ground truth was incomplete
./bin/benchmrk triage <run-id> --set 43 --disposition tp \
  --notes "verified: req.query.id reaches db.query unsanitized at line 82"

# This one's noise — false positive
./bin/benchmrk triage <run-id> --set 44 --disposition fp \
  --notes "the 'password' variable is a bcrypt hash, not plaintext"

# Not sure yet
./bin/benchmrk triage <run-id> --set 45 --disposition needs_review
```

When you're done:

```bash
# tp dispositions → new ground-truth entries
./bin/benchmrk triage <run-id> --promote

# Re-score: the promoted tps are now in the answer key
./bin/benchmrk analyze <run-id>
```

Your benchmark just got more complete. The next scanner you run is
measured against the bugs this one found.

---

## Scenario 5: Cross-tool comparison

semgrep vs bandit on a Python codebase.

```bash
# Use a Python target you have ground truth for — a Flask/Django app,
# DVWA-style practice target, your own code.
./bin/benchmrk corpus add my-python-app --source /path/to/app --language python
./bin/benchmrk annotate import my-python-app --file my-python-vulns.json

./bin/benchmrk scanner register semgrep-python \
  --version "$(semgrep --version)" --mode local \
  --executable ./examples/wrappers/semgrep.sh \
  --config '{"env": {"SEMGREP_RULES": "p/python"}}' \
  --output-format sarif

./bin/benchmrk scanner register bandit \
  --version "$(bandit --version 2>&1 | head -1 | awk '{print $2}')" --mode local \
  --executable ./examples/wrappers/bandit.sh \
  --output-format sarif

./bin/benchmrk experiment create semgrep-vs-bandit \
  --scanners <semgrep-id>,<bandit-id> --projects <project-id> --iterations 3
./bin/benchmrk experiment run <exp-id>
./bin/benchmrk compare semgrep-python bandit -p my-python-app
```

The interesting comparison here isn't the headline F1 — it's the
**complement**. Which bugs does bandit find that semgrep misses, and
vice versa?

```bash
./bin/benchmrk compare semgrep-python bandit -p my-python-app --coverage
```

The `--coverage` section shows:

- **Union recall vs. best single** — how much more you catch running
  both instead of just the better one. If the gap is ~0, one of them
  is redundant.
- **Marginal contribution per scanner** — the vulns *only that
  scanner* catches, with tiers. This is the cost of dropping it.
  `[must:1]` in bandit's row means there's a critical bug only bandit
  finds; you can't drop bandit. Empty row → redundant given the other.
- **Caught by none** — your blind spots regardless. `must`-tier
  entries here are either a ground-truth error or a hole in every
  tool's rules.
- **Flaky coverage** — vulns caught in some iterations but not all.
  Distrust these first when two compare runs disagree.

If the marginal rows are both empty, pick the one with better
precision. If both have `must`-tier uniques, you need both.

---

## Scenario 6: Is our ground truth any good?

You wrote the annotations. Maybe you were wrong about one.

Have a second person annotate independently, merge the lists (both
names in `annotated_by`), then:

```bash
# Score normally
./bin/benchmrk compare a b c -p project

# Score only high-consensus vulns
./bin/benchmrk compare a b c -p project --min-consensus 2
```

If the rankings differ, your single-annotator calls were load-bearing.
Look at which vulns have consensus 1 and double-check them.

---

## Common mistakes

**Comparing runs from different benchmrk versions without re-scoring.**
Watch for the `⚠ matcher version differs` warning. Fix:
`sqlite3 <db> "DELETE FROM finding_matches;"` then re-run `compare`.

**`--iterations 1` and then trusting small F1 differences.**
Single-run F1 has no error bars. A 0.02 gap might be noise. Set
`--iterations 3` at minimum.

**One vulnerability annotated as six separate entries.**
Six IDOR endpoints with the same root cause are one vulnerability with
six `evidence` rows. Otherwise a scanner that finds one endpoint scores
1 TP + 5 FN and looks terrible for what was actually a successful
detection.

**No `status: invalid` entries.**
Without known-not-bugs, you can't measure precision against anything.
Every unmatched finding just counts as FP. Add some decoys.

**Writing `cwes: ["CWE-20"]` for everything.**
CWE-20 (Improper Input Validation) is the abstract parent of half the
tree. Use the specific weakness. If you're not sure which one the
scanner will pick, list several — that's what the array is for.
