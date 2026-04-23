#!/usr/bin/env bash
#
# benchmrk wrapper for GitHub CodeQL (https://codeql.github.com)
#
# CodeQL is a two-phase tool: build a database from the source, then
# run queries against it. Database creation is the slow part — minutes
# on a small project, much longer on large ones. Register this scanner
# with a generous --timeout:
#
#   benchmrk scan codeql <project> --timeout 60
#
# Compiled languages (Java, C/C++, Go, C#) need to OBSERVE the build.
# If your project has a nonstandard build, set CODEQL_BUILD_COMMAND.
# Interpreted languages (JavaScript, Python, Ruby) extract without
# building.
#
# benchmrk sets:
#   TARGET_DIR       absolute path to the corpus
#   OUTPUT_DIR       absolute path where results.sarif must be written
#   TARGET_LANGUAGE  from corpus add --language (may be empty)
#
# Config env (via --config '{"env": {...}}'):
#   CODEQL_LANGUAGE       database language. Falls back to TARGET_LANGUAGE.
#                         javascript | python | ruby | java | go | cpp | csharp
#   CODEQL_SUITE          query suite (default: <lang>-security-and-quality)
#                         Examples for JS:
#                           javascript-code-scanning
#                           javascript-security-extended
#                           javascript-security-and-quality
#   CODEQL_BUILD_COMMAND  build command for compiled languages
#                         (e.g. "mvn clean compile", "make")
#   CODEQL_THREADS        parallelism (default: 0 = all cores)
#   CODEQL_DB_CACHE       directory for cached databases. When set and a
#                         database for this target already exists there,
#                         skip creation. Big speedup across iterations —
#                         DB creation dominates runtime and the source
#                         hasn't changed between iterations.
#
set -euo pipefail

: "${TARGET_DIR:?TARGET_DIR not set by benchmrk}"
: "${OUTPUT_DIR:?OUTPUT_DIR not set by benchmrk}"

LANG="${CODEQL_LANGUAGE:-${TARGET_LANGUAGE:-}}"
if [[ -z "$LANG" ]]; then
  echo "error: no language set. Use --config '{\"env\":{\"CODEQL_LANGUAGE\":\"javascript\"}}'" >&2
  echo "       or add the project with 'corpus add --language <lang>'." >&2
  exit 1
fi

SUITE="${CODEQL_SUITE:-${LANG}-security-and-quality}"
THREADS="${CODEQL_THREADS:-0}"

echo "codeql wrapper" >&2
echo "  target:   $TARGET_DIR" >&2
echo "  language: $LANG" >&2
echo "  suite:    $SUITE" >&2

# ── Database: cached or fresh ────────────────────────────────────────
#
# When CODEQL_DB_CACHE is set, the DB lives at a stable path keyed on
# the target dir. Across iterations of the same experiment, iteration 1
# pays the creation cost and 2+ reuse it. Without the cache, the DB
# goes in OUTPUT_DIR and is recreated every run.

if [[ -n "${CODEQL_DB_CACHE:-}" ]]; then
  # Hash the target path so different projects don't collide. The
  # target CONTENT isn't hashed — if you edit the source, clear the
  # cache manually. Iteration runs don't edit source, so this is fine.
  key=$(printf '%s' "$TARGET_DIR" | shasum -a 256 | cut -c1-16)
  DB="$CODEQL_DB_CACHE/codeql-db-$LANG-$key"
  mkdir -p "$CODEQL_DB_CACHE"
else
  DB="$OUTPUT_DIR/codeql-db"
fi

if [[ -d "$DB" && -f "$DB/codeql-database.yml" ]]; then
  echo "  database: $DB (cached)" >&2
else
  echo "  database: $DB (creating — this is the slow step)" >&2
  rm -rf "$DB"

  create=(
    codeql database create "$DB"
    --language "$LANG"
    --source-root "$TARGET_DIR"
    --threads "$THREADS"
    --overwrite
  )
  # Compiled languages: codeql must trace the build to see every
  # compilation unit. Interpreted languages: --no-run-unnecessary-builds
  # skips the build tracer entirely and just extracts source.
  if [[ -n "${CODEQL_BUILD_COMMAND:-}" ]]; then
    create+=(--command "$CODEQL_BUILD_COMMAND")
  else
    create+=(--no-run-unnecessary-builds)
  fi

  "${create[@]}"
fi

# ── Analyze ──────────────────────────────────────────────────────────
#
# --sarif-category: disambiguates when multiple SARIF files for the
# same commit are uploaded to GitHub code scanning. Harmless for
# benchmrk but good hygiene if you also upload these.

codeql database analyze "$DB" \
  --format sarif-latest \
  --output "$OUTPUT_DIR/results.sarif" \
  --threads "$THREADS" \
  --sarif-category "benchmrk-$LANG" \
  -- "$SUITE"

if [[ ! -s "$OUTPUT_DIR/results.sarif" ]]; then
  echo "error: codeql did not produce $OUTPUT_DIR/results.sarif" >&2
  exit 1
fi
