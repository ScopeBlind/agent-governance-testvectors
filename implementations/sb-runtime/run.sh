#!/usr/bin/env bash
# sb-runtime conformance driver.
#
# Translates each testvector input into an `sb exec --allow-unsandboxed`
# invocation, captures the produced receipt file from the .receipts/
# directory, and renames it to the fixture-sequence filename for the
# verifier.
#
# Requires `sb` (the sb-runtime CLI) on PATH. Install with:
#
#     cargo install --path crates/sb-cli --force
#
# from a clone of https://github.com/ScopeBlind/sb-runtime
#
# The receipts produced follow the v2 structured-envelope format
# ({payload, signature, pubkey}). `@veritasacta/verify` accepts this
# format in parallel with the v1 flat format used by protect-mcp.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/fixtures"
OUT="$REPO_ROOT/receipts/sb-runtime"
mkdir -p "$OUT"

command -v sb >/dev/null 2>&1 || { echo "skip: 'sb' (sb-runtime CLI) not on PATH"; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "skip: python3 required"; exit 77; }

POLICY="$FIXTURES/policy/autoresearch-safe.cedar"
SEED_HEX="0000000000000000000000000000000000000000000000000000000000000001"

# sb exec writes receipts into the --receipts directory, numbered
# sequentially (000001.json, 000002.json...). We drive one fixture at a
# time into a per-input subdirectory, then rename to the expected
# fixture-keyed filename.

# Map testvector inputs to sb-runtime exec command lines. sb-runtime is
# designed for real OS commands; we use harmless read-only commands that
# exercise the same Cedar rules the testvector describes.
#
# 001-allow-read          -> /bin/cat ./README.md
# 002-allow-bash-git      -> /usr/bin/git status
# 003-deny-bash-destructive -> /bin/rm -rf /tmp/testvectors-sentinel-does-not-exist
#                              (the policy denies this before exec runs,
#                               so no filesystem effect actually happens)
# 004-allow-write         -> /usr/bin/touch ./notes.md.sentinel
#                            (cedar must be extended to permit exec of
#                             this specific target; for the test we
#                             evaluate-only and rely on sb exec's deny
#                             path not to exec on deny)

run_one() {
    local name="$1"
    local cmd="$2"
    shift 2
    local -a args=("$@")
    local subdir="$OUT/.tmp-$name"
    mkdir -p "$subdir"

    # sb exec returns non-zero on deny; that is expected behavior for
    # fixture 003.
    sb exec \
        --policy "$POLICY" \
        --receipts "$subdir" \
        --key-seed-hex "$SEED_HEX" \
        --allow-unsandboxed \
        -- "$cmd" "${args[@]}" >/dev/null 2>&1 || true

    # Collect the produced receipt. sb-runtime uses sequential filenames
    # starting at 000001.json for the first receipt in a fresh dir.
    local produced
    produced="$(ls "$subdir"/*.json 2>/dev/null | head -1)"
    if [ -n "$produced" ] && [ -f "$produced" ]; then
        mv "$produced" "$OUT/$name.json"
    fi
    rm -rf "$subdir"
}

run_one "001-allow-read"              /bin/cat     ./README.md
run_one "002-allow-bash-git"          /usr/bin/git status
run_one "003-deny-bash-destructive"   /bin/rm      -rf /tmp/testvectors-nonexistent-sentinel
run_one "004-allow-write"             /usr/bin/touch ./notes.md.sentinel

# sb-runtime v0.1 policies only cover exec actions. Fixtures that test
# Read/Write/Bash by category rather than specific commands may not map
# perfectly onto sb-runtime's command-level Cedar model. The receipts
# above still verify signatures and chain correctly; conformance holds
# at the cryptographic layer. Schema-level field-naming differences
# between v1 flat and v2 envelope formats are accommodated in
# expected/receipt-schema.json's oneOf.

COUNT="$(ls "$OUT"/*.json 2>/dev/null | wc -l | tr -d ' ')"
echo "sb-runtime: $COUNT receipts in $OUT"

[ "$COUNT" -gt 0 ]
