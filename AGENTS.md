# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

**For structured CLI workflows** (running scans, writing annotations, comparing tools, triaging findings), see **[SKILLS.md](SKILLS.md)** — it has trigger conditions, exact command sequences, and domain-aware guardrails for every operation.

## Quick Reference

**Issue tracking (bd)**
```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

**benchmrk itself** — full workflows in [SKILLS.md](SKILLS.md)
```bash
./bin/benchmrk scan <scanner> <project>       # One-off run → run-id
./bin/benchmrk analyze <run-id> --detail      # Score + per-vuln breakdown
./bin/benchmrk compare <a> <b> -p <project>   # Head-to-head
./bin/benchmrk import <scanner> <project> <f> # Import SARIF without running
./bin/benchmrk review run <run-id> -o r.html  # Triage page, one card/finding
./bin/benchmrk logs <run-id>                  # Scanner stdout/stderr
```

## When things break mid-task

- **Build fails** → `go build ./... 2>&1` and read the first error, not the last. Fix before continuing.
- **Tests fail** → run the single failing test with `go test -run TestName ./path/` before touching anything else. The failure message usually names the expectation.
- **Scan fails** → `./bin/benchmrk logs <run-id>` first. Most failures are wrapper-script bugs (wrong env var, wrong output path), not benchmrk bugs.
- **`compare` warns about matcher/annotation mismatch** → `./bin/benchmrk rescore <project>`. Safe — only derived match rows are touched.
- **Can't tell if your change broke scoring** → run `make test`. The matcher determinism tests and metrics tests catch most regressions.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

