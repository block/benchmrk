#!/usr/bin/env bash
# quick-run.sh — A/B test scanner rulesets with benchmrk
#
# Demonstrates benchmrk's core value proposition: comparing SAST scanner
# configurations side-by-side on a vulnerable test application with
# ground-truth annotations.
#
# What this script does:
#   1. Builds benchmrk (if needed)
#   2. Clones the vulnerable todo app as the test corpus
#   3. Imports 40+ ground-truth annotations (valid vulns + known false positives)
#   4. Registers scanner variants with different rulesets/configs
#   5. Runs each scanner variant against the corpus
#   6. Compares results and generates a report
#
# Prerequisites:
#   - Go 1.25+ (to build benchmrk)
#   - semgrep installed locally (pip install semgrep)
#   - Git (to clone the test corpus)
#   - Optional: codeql CLI for CodeQL scanner variants
#   - Optional: Docker for Docker-mode scanner variants
#
# Usage:
#   ./examples/quick-run.sh              # Run from repo root
#   ./examples/quick-run.sh --semgrep    # Semgrep variants only
#   ./examples/quick-run.sh --codeql     # CodeQL variants only
#   ./examples/quick-run.sh --docker     # Docker variants only
#   ./examples/quick-run.sh --all        # All variants (local + Docker)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCHMRK="$REPO_ROOT/bin/benchmrk"
# NOTE: The default corpus below is a private repo. External users
# should set CORPUS_REPO to a repository they can clone — any codebase
# with a matching annotations file works. See examples/README.md for
# public alternatives (Juice Shop, WebGoat).
CORPUS_DIR="${CORPUS_DIR:-/tmp/vulnerable-todoapp}"
CORPUS_REPO="${CORPUS_REPO:-org-49461806@github.com:squareup/personal-ccarpene-blk-vulnerable-todoapp.git}"
PROJECT_NAME="${PROJECT_NAME:-vulnerable-todoapp}"
ANNOTATIONS="$REPO_ROOT/sample-app-annotations.json"
EXAMPLES_DIR="$REPO_ROOT/examples"

# Parse flags
RUN_SEMGREP=false
RUN_CODEQL=false
RUN_DOCKER=false

if [ $# -eq 0 ]; then
    # Default: run local semgrep (most likely to be available)
    RUN_SEMGREP=true
fi

for arg in "$@"; do
    case "$arg" in
        --semgrep)  RUN_SEMGREP=true ;;
        --codeql)   RUN_CODEQL=true ;;
        --docker)   RUN_DOCKER=true ;;
        --all)      RUN_SEMGREP=true; RUN_CODEQL=true; RUN_DOCKER=true ;;
        --help|-h)
            echo "Usage: $0 [--semgrep] [--codeql] [--docker] [--all]"
            echo ""
            echo "Flags:"
            echo "  --semgrep  Run local Semgrep scanner variants (default if no flags)"
            echo "  --codeql   Run local CodeQL scanner variants"
            echo "  --docker   Run Docker-based scanner variants"
            echo "  --all      Run all scanner variants"
            echo ""
            echo "Prerequisites:"
            echo "  --semgrep: semgrep CLI (pip install semgrep)"
            echo "  --codeql:  codeql CLI"
            echo "  --docker:  Docker daemon running"
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg (use --help for usage)"
            exit 1
            ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────────────────

step=0
step() {
    step=$((step + 1))
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Step $step: $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

info() { echo "  ℹ  $1"; }
ok()   { echo "  ✓  $1"; }
warn() { echo "  ⚠  $1"; }
fail() { echo "  ✗  $1"; exit 1; }

# Track registered scanner names for final comparison
SCANNERS_REGISTERED=()

# ── Step 1: Build benchmrk ────────────────────────────────────────────────────

step "Build benchmrk"

info "Building benchmrk (incremental)..."
(cd "$REPO_ROOT" && go build -o bin/benchmrk ./cmd/benchmrk)
ok "Built $BENCHMRK"

# ── Step 2: Initialize database ───────────────────────────────────────────────

step "Initialize database"

"$BENCHMRK" migrate
ok "Database migrations applied"

# ── Step 3: Clone test corpus ─────────────────────────────────────────────────

step "Clone vulnerable todo app"

if [ -d "$CORPUS_DIR" ]; then
    info "Corpus already cloned at $CORPUS_DIR"
    (cd "$CORPUS_DIR" && git pull --quiet 2>/dev/null || true)
    ok "Corpus up to date"
else
    info "Cloning $CORPUS_REPO..."
    if ! git clone "$CORPUS_REPO" "$CORPUS_DIR" 2>&1; then
        echo
        echo "ERROR: Could not clone the default corpus repo."
        echo
        echo "The default is a private Square repository. To use your own corpus:"
        echo
        echo "  CORPUS_REPO=https://github.com/juice-shop/juice-shop \\"
        echo "  CORPUS_DIR=/tmp/juice-shop \\"
        echo "  PROJECT_NAME=juice-shop \\"
        echo "    $0"
        echo
        echo "You'll also need an annotation file for that corpus — see"
        echo "examples/README.md and examples/juice-shop-vulns.json."
        exit 1
    fi
    ok "Cloned to $CORPUS_DIR"
fi

# ── Step 4: Register corpus project ───────────────────────────────────────────

step "Register corpus project"

"$BENCHMRK" corpus add "$PROJECT_NAME" \
    --source "$CORPUS_DIR" \
    --language javascript 2>/dev/null || {
    info "Project may already exist, continuing..."
}
ok "Project '$PROJECT_NAME' registered"

# ── Step 5: Import ground-truth annotations ────────────────────────────────────

step "Import ground-truth annotations"

if [ ! -f "$ANNOTATIONS" ]; then
    fail "Annotations file not found: $ANNOTATIONS"
fi

"$BENCHMRK" annotate import "$PROJECT_NAME" --file "$ANNOTATIONS" --replace
ok "Annotations imported from $ANNOTATIONS"

# ── Step 6: Register and run scanner variants ──────────────────────────────────

# ── 6a: Local Semgrep variants ──

if $RUN_SEMGREP; then
    step "Register & run Semgrep local scanner variants"

    if ! command -v semgrep &>/dev/null; then
        warn "semgrep not found — skipping local Semgrep variants"
        warn "Install with: pip install semgrep"
    else
        SEMGREP_VERSION=$(semgrep --version 2>/dev/null || echo "unknown")
        info "Found semgrep $SEMGREP_VERSION"

        # Semgrep security-audit
        info "Registering semgrep-security-audit..."
        "$BENCHMRK" scanner register semgrep-security-audit \
            --version "$SEMGREP_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/semgrep-local/semgrep-security-audit.sh" \
            --output-format semgrep-json 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-security-audit")

        # Semgrep OWASP
        info "Registering semgrep-owasp..."
        "$BENCHMRK" scanner register semgrep-owasp \
            --version "$SEMGREP_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/semgrep-local/semgrep-owasp.sh" \
            --output-format semgrep-json 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-owasp")

        # Semgrep auto (broader rule coverage)
        info "Registering semgrep-auto-broad..."
        "$BENCHMRK" scanner register semgrep-auto-broad \
            --version "$SEMGREP_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/semgrep-local/semgrep-security-audit.sh" \
            --config '{"output_format":"semgrep-json","env":{"SEMGREP_CONFIGS":"auto"}}' 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-auto-broad")

        # Semgrep JavaScript-specific pack
        info "Registering semgrep-javascript-pack..."
        "$BENCHMRK" scanner register semgrep-javascript-pack \
            --version "$SEMGREP_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/semgrep-local/semgrep-security-audit.sh" \
            --config '{"output_format":"semgrep-json","env":{"SEMGREP_CONFIGS":"p/javascript"}}' 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-javascript-pack")

        # Semgrep Node.js-specific pack
        info "Registering semgrep-nodejs-pack..."
        "$BENCHMRK" scanner register semgrep-nodejs-pack \
            --version "$SEMGREP_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/semgrep-local/semgrep-security-audit.sh" \
            --config '{"output_format":"semgrep-json","env":{"SEMGREP_CONFIGS":"p/nodejs"}}' 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-nodejs-pack")

        # Semgrep composite pack (max coverage for demo)
        info "Registering semgrep-composite-max..."
        "$BENCHMRK" scanner register semgrep-composite-max \
            --version "$SEMGREP_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/semgrep-local/semgrep-security-audit.sh" \
            --config '{"output_format":"semgrep-json","env":{"SEMGREP_CONFIGS":"auto,p/javascript,p/nodejs"}}' 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-composite-max")

        # Run scans
        info "Running semgrep-security-audit scan..."
        "$BENCHMRK" scan semgrep-security-audit "$PROJECT_NAME" --timeout 15
        ok "semgrep-security-audit scan complete"

        info "Running semgrep-owasp scan..."
        "$BENCHMRK" scan semgrep-owasp "$PROJECT_NAME" --timeout 15
        ok "semgrep-owasp scan complete"

        info "Running semgrep-auto-broad scan..."
        "$BENCHMRK" scan semgrep-auto-broad "$PROJECT_NAME" --timeout 15
        ok "semgrep-auto-broad scan complete"

        info "Running semgrep-javascript-pack scan..."
        "$BENCHMRK" scan semgrep-javascript-pack "$PROJECT_NAME" --timeout 15
        ok "semgrep-javascript-pack scan complete"

        info "Running semgrep-nodejs-pack scan..."
        "$BENCHMRK" scan semgrep-nodejs-pack "$PROJECT_NAME" --timeout 15
        ok "semgrep-nodejs-pack scan complete"

        info "Running semgrep-composite-max scan..."
        "$BENCHMRK" scan semgrep-composite-max "$PROJECT_NAME" --timeout 15
        ok "semgrep-composite-max scan complete"
    fi
fi

# ── 6b: Local CodeQL variants ──

if $RUN_CODEQL; then
    step "Register & run CodeQL local scanner variants"

    if ! command -v codeql &>/dev/null; then
        warn "codeql not found — skipping local CodeQL variants"
        warn "Install from: https://github.com/github/codeql-cli-binaries/releases"
    else
        CODEQL_VERSION=$(codeql version --format=terse 2>/dev/null || echo "unknown")
        info "Found codeql $CODEQL_VERSION"

        # CodeQL security-extended
        info "Registering codeql-security-extended..."
        "$BENCHMRK" scanner register codeql-security-extended \
            --version "$CODEQL_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/codeql-local/codeql-security-extended.sh" 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("codeql-security-extended")

        # CodeQL security-and-quality
        info "Registering codeql-security-quality..."
        "$BENCHMRK" scanner register codeql-security-quality \
            --version "$CODEQL_VERSION" \
            --mode local \
            --executable "$EXAMPLES_DIR/scanners/codeql-local/codeql-security-quality.sh" 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("codeql-security-quality")

        # Run scans
        info "Running codeql-security-extended scan..."
        "$BENCHMRK" scan codeql-security-extended "$PROJECT_NAME" --timeout 30
        ok "codeql-security-extended scan complete"

        info "Running codeql-security-quality scan..."
        "$BENCHMRK" scan codeql-security-quality "$PROJECT_NAME" --timeout 30
        ok "codeql-security-quality scan complete"
    fi
fi

# ── 6c: Docker variants ──

if $RUN_DOCKER; then
    step "Register & run Docker scanner variants"

    if ! docker info &>/dev/null 2>&1; then
        warn "Docker not available — skipping Docker variants"
        warn "Start Docker Desktop or the Docker daemon"
    else
        info "Docker is available"

        # Build and register Semgrep Docker variants
        info "Building semgrep-security-audit Docker image..."
        docker build \
            -f "$EXAMPLES_DIR/scanners/semgrep-docker/Dockerfile.security-audit" \
            -t benchmrk-scanner-semgrep-security-audit:latest \
            "$EXAMPLES_DIR/scanners/semgrep-docker/"
        ok "Built benchmrk-scanner-semgrep-security-audit:latest"

        info "Registering semgrep-security-audit-docker..."
        "$BENCHMRK" scanner register semgrep-security-audit-docker \
            --version 1.0.0 \
            --image benchmrk-scanner-semgrep-security-audit:latest \
            --output-format semgrep-json 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-security-audit-docker")

        info "Building semgrep-owasp Docker image..."
        docker build \
            -f "$EXAMPLES_DIR/scanners/semgrep-docker/Dockerfile.owasp" \
            -t benchmrk-scanner-semgrep-owasp:latest \
            "$EXAMPLES_DIR/scanners/semgrep-docker/"
        ok "Built benchmrk-scanner-semgrep-owasp:latest"

        info "Registering semgrep-owasp-docker..."
        "$BENCHMRK" scanner register semgrep-owasp-docker \
            --version 1.0.0 \
            --image benchmrk-scanner-semgrep-owasp:latest \
            --output-format semgrep-json 2>/dev/null || info "Already registered"
        SCANNERS_REGISTERED+=("semgrep-owasp-docker")

        # Run Docker scans
        info "Running semgrep-security-audit-docker scan..."
        "$BENCHMRK" scan semgrep-security-audit-docker "$PROJECT_NAME" --timeout 15
        ok "semgrep-security-audit-docker scan complete"

        info "Running semgrep-owasp-docker scan..."
        "$BENCHMRK" scan semgrep-owasp-docker "$PROJECT_NAME" --timeout 15
        ok "semgrep-owasp-docker scan complete"
    fi
fi

# ── Step 7: Compare results ───────────────────────────────────────────────────

step "Compare scanner results"

if [ ${#SCANNERS_REGISTERED[@]} -lt 2 ]; then
    warn "Need at least 2 scanner variants to compare. Only registered: ${SCANNERS_REGISTERED[*]:-none}"
    echo ""
    echo "Listing all scanners:"
    "$BENCHMRK" scanner list
else
    info "Comparing: ${SCANNERS_REGISTERED[*]}"
    "$BENCHMRK" compare "${SCANNERS_REGISTERED[@]}" --project "$PROJECT_NAME"
fi

# ── Step 8: Show individual analysis ──────────────────────────────────────────

step "Individual scanner analysis"

for scanner_name in "${SCANNERS_REGISTERED[@]}"; do
    echo ""
    echo "── $scanner_name ──"
    # Find the latest run for this scanner — get the last run ID from the scan output
    # Use analyze on the most recent run (we ran them sequentially so they're in order)
    echo "(Use 'benchmrk analyze <run-id>' for detailed per-finding breakdown)"
done

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done! A/B testing complete."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Scanners tested: ${SCANNERS_REGISTERED[*]}"
echo ""
echo "Next steps:"
echo "  • View detailed analysis:    $BENCHMRK analyze <run-id> --detail"
echo "  • Triage unmatched findings: $BENCHMRK triage <run-id>"
echo "  • Generate a report:         $BENCHMRK report <experiment-id> --format html"
echo ""
