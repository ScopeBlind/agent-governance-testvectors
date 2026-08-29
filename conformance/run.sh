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

# Track outcomes so the script's exit status reflects the verdict it prints.
# Previously the loop ended without an exit, so run.sh returned the status of
# its last echo: CI stayed green while every implementation was reported
# NON-CONFORMANT. A gate that prints the right answer and returns 0 is not a
# gate. Reported in #13.
FAILED=0
CHECKED=0

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
        FAILED=$((FAILED+1))
        continue
    fi
    echo "--- verifying $impl output ---"
    ./conformance/verify.sh "receipts/$impl"
    V=$?
    CHECKED=$((CHECKED+1))
    if [ "$V" -eq 0 ]; then
        echo "${GREEN}CONFORMANT${NC}: $impl"
    else
        echo "${RED}NON-CONFORMANT${NC}: $impl"
        FAILED=$((FAILED+1))
    fi
done

echo ""
echo "==========================================="
echo "  $CHECKED implementation(s) verified, $FAILED failed"
echo "==========================================="

# An empty run is a failure too. If no implementation was exercised, the suite
# has proved nothing, and reporting success would repeat the bug above in a
# different costume.
if [ "$CHECKED" -eq 0 ]; then
    echo "${RED}ERROR${NC}: no implementation was verified"
    exit 1
fi

[ "$FAILED" -eq 0 ]
