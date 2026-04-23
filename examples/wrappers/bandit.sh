#!/usr/bin/env bash
#
# benchmrk wrapper for bandit (https://bandit.readthedocs.io)
# Python-only SAST.
#
# benchmrk sets:
#   TARGET_DIR   absolute path to the corpus
#   OUTPUT_DIR   absolute path where results.sarif must be written
#
# Config env (via --config '{"env": {...}}'):
#   BANDIT_CONFIDENCE   low | medium | high  (default: low — report everything)
#   BANDIT_SEVERITY     low | medium | high  (default: low)
#   BANDIT_CONFIG       path to a bandit.yaml (default: none)
#
# Requires bandit with the sarif formatter:
#   pip install 'bandit[sarif]'
#
set -euo pipefail

: "${TARGET_DIR:?TARGET_DIR not set by benchmrk}"
: "${OUTPUT_DIR:?OUTPUT_DIR not set by benchmrk}"

CONF="${BANDIT_CONFIDENCE:-low}"
SEV="${BANDIT_SEVERITY:-low}"

echo "bandit wrapper" >&2
echo "  target:     $TARGET_DIR" >&2
echo "  confidence: $CONF" >&2
echo "  severity:   $SEV" >&2

# Build the -i / -l repetition flags bandit expects.
# low=1, medium=2, high=3 repetitions.
level_flag() {
  case "$1" in
    high)   echo "$2$2$2" ;;
    medium) echo "$2$2" ;;
    *)      echo "$2" ;;
  esac
}

args=(
  --recursive
  --format sarif
  --output "$OUTPUT_DIR/results.sarif"
  "$(level_flag "$CONF" -i)"
  "$(level_flag "$SEV" -l)"
)
[[ -n "${BANDIT_CONFIG:-}" ]] && args+=(--configfile "$BANDIT_CONFIG")

# bandit exits 1 when it finds issues. That's not a failure for our
# purposes — the SARIF file is what matters.
bandit "${args[@]}" "$TARGET_DIR" || true

if [[ ! -s "$OUTPUT_DIR/results.sarif" ]]; then
  echo "error: bandit did not produce $OUTPUT_DIR/results.sarif" >&2
  echo "  (is the sarif extra installed?  pip install 'bandit[sarif]')" >&2
  exit 1
fi
