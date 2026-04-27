#!/usr/bin/env bash
#
# benchmrk wrapper for semgrep (https://semgrep.dev)
#
# benchmrk sets:
#   TARGET_DIR   absolute path to the corpus
#   OUTPUT_DIR   absolute path where results.sarif must be written
#
# Scanner config (--config '{"env": {...}}') adds more env vars. This
# wrapper reads:
#   SEMGREP_RULES   ruleset to use (default: auto)
#                   Examples: auto, p/security-audit, p/owasp-top-ten,
#                             p/javascript, ./path/to/custom-rules/
#   SEMGREP_EXTRA   extra CLI args, space-separated (default: empty)
#
# Register multiple ruleset variants off this one script:
#
#   benchmrk scanner register semgrep-audit --mode local \
#     --executable ./examples/wrappers/semgrep.sh \
#     --config '{"env": {"SEMGREP_RULES": "p/security-audit"}}'
#
#   benchmrk scanner register semgrep-owasp --mode local \
#     --executable ./examples/wrappers/semgrep.sh \
#     --config '{"env": {"SEMGREP_RULES": "p/owasp-top-ten"}}'
#
set -euo pipefail

: "${TARGET_DIR:?TARGET_DIR not set by benchmrk}"
: "${OUTPUT_DIR:?OUTPUT_DIR not set by benchmrk}"

RULES="${SEMGREP_RULES:-auto}"
EXTRA="${SEMGREP_EXTRA:-}"

echo "semgrep wrapper" >&2
echo "  target: $TARGET_DIR" >&2
echo "  rules:  $RULES" >&2

# --no-git-ignore: scan everything in the target, not just tracked files.
#   The corpus might be a bare copy without .git.
# --error: non-zero exit on findings. We ignore the exit code — benchmrk
#   decides success by whether results.sarif appeared, not by exit status.
# shellcheck disable=SC2086  # EXTRA is intentionally word-split
semgrep scan \
  --config "$RULES" \
  --sarif \
  --output "$OUTPUT_DIR/results.sarif" \
  --no-git-ignore \
  --metrics off \
  $EXTRA \
  "$TARGET_DIR" || true

if [[ ! -s "$OUTPUT_DIR/results.sarif" ]]; then
  echo "error: semgrep did not produce $OUTPUT_DIR/results.sarif" >&2
  exit 1
fi
