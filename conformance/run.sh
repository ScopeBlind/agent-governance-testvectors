#!/usr/bin/env bash
# run.sh - exercise every implementation under implementations/ against the
# fixtures, collecting receipts into receipts/<impl>/, then verifying each.
#
# Each implementation's directory should contain an executable run.sh that:
#   - reads fixtures from ../../fixtures/
#   - writes receipts to ../../receipts/<impl>/

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

mkdir -p receipts

GREEN="$(printf '\033[0;32m')"
RED="$(printf '\033[0;31m')"
NC="$(printf '\033[0m')"

for impl_dir in implementations/*/; do
    impl="$(basename "$impl_dir")"
    echo ""
    echo "==========================================="
    echo "  Implementation: $impl"
    echo "==========================================="
    if [ ! -x "$impl_dir/run.sh" ]; then
        echo "${RED}SKIP${NC}: no run.sh in $impl_dir (placeholder implementation)"
        continue
    fi
    rm -rf "receipts/$impl"
    mkdir -p "receipts/$impl"
    (cd "$impl_dir" && ./run.sh)
    RC=$?
    if [ "$RC" -ne 0 ]; then
        echo "${RED}FAIL${NC}: $impl run.sh exited $RC"
        continue
    fi
    echo "--- verifying $impl output ---"
    ./conformance/verify.sh "receipts/$impl"
    V=$?
    if [ "$V" -eq 0 ]; then
        echo "${GREEN}CONFORMANT${NC}: $impl"
    else
        echo "${RED}NON-CONFORMANT${NC}: $impl"
    fi
done
