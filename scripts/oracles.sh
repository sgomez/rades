#!/usr/bin/env bash
# oracles.sh — Run all oracles against the manifest.
#
# Usage: scripts/oracles.sh [base-dir]
# Default base-dir is tests/oracles/.

set -euo pipefail

BASE_DIR="${1:-tests/oracles}"
BASE_DIR="$(cd "$BASE_DIR" && pwd)"

echo "=== Oracles ==="
echo "Base directory: $BASE_DIR"
echo ""

# ── DSS oracle ─────────────────────────────────────────────
echo "--- DSS ---"

# Check if JBang is available
if ! command -v jbang &>/dev/null; then
    echo "JBang not found. Install it to run DSS oracle."
    echo "  brew install jbang"
    echo ""
    echo "Skipping DSS oracle (not installed)."
else
    # Run the DSS validator via JBang
    jbang --fresh tests/oracles/dss/validate.java "$BASE_DIR" 2>&1 || {
        echo "DSS oracle failed."
        exit 1
    }
fi

echo ""
echo "=== Oracles complete ==="
