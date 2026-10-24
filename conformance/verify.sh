#!/usr/bin/env bash
# verify.sh - run the three conformance checks on a directory of receipts.
#
# Usage: ./conformance/verify.sh <receipts_dir>
#
# Exit codes:
#   0   all three checks passed
#   1   one or more checks failed
#   2   usage error or dependency missing

set -uo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <receipts_dir>"
    exit 2
fi

RECEIPTS_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -d "$RECEIPTS_DIR" ]; then
    echo "error: $RECEIPTS_DIR does not exist"
    exit 2
fi

for cmd in python3 npx; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "error: '$cmd' required"; exit 2; }
done

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# ----- Check 1: schema conformance --------------------------------------------
# expected/receipt-schema.json is a oneOf over the two shapes the published
# verifier reads: the Acta 2.1 envelope and decision_receipt (v1 flat and the
# v2 envelope are recorded there, not accepted). It is validated with a JSON Schema validator (ajv, draft-07), not a
# hand-rolled field test: the field test drifted permissive (it never tested
# receipt_id and accepted a bare string where the schema requires an object),
# so a vector could pass Check 1 and fail the schema with nothing saying so
# (issue #21).
echo ""
echo "=== Check 1: schema conformance (expected/receipt-schema.json, draft-07; two accepted shapes) ==="
SCHEMA="$REPO_ROOT/expected/receipt-schema.json"
for f in "$RECEIPTS_DIR"/*.json; do
    [ -e "$f" ] || continue
    if npx --yes -p ajv-cli@5 -p ajv-formats@2 ajv validate --spec=draft7 -c ajv-formats -s "$SCHEMA" -d "$f" --errors=text >/tmp/ajv-out.txt 2>&1; then
        pass "schema ok: $(basename "$f")"
    else
        sed 's/^/  /' /tmp/ajv-out.txt | head -8
        fail "schema fail: $(basename "$f")"
    fi
done

# ----- Check 2: signature verification ----------------------------------------
#
# One invocation per receipt, not a glob.
#
# @veritasacta/verify takes a single <file.json>. Given several positionally it
# verifies only the LAST one and exits on that, printing one verdict line for
# the whole set. Measured against a four-receipt directory by tampering each
# position in turn, the glob form reported success for three of the four:
#
#     tampered receipt-0001 -> exit 0
#     tampered receipt-0002 -> exit 0
#     tampered receipt-0003 -> exit 0
#     tampered receipt-0004 -> exit 1
#
# So an implementation could forge three of its four receipts and this check
# would report "all signatures verify". The verifier is correct; handed the
# tampered file alone it exits 1. The invocation was the defect. (Issue #13,
# finding 7.)
#
# The pass line is deliberately after the loop rather than inside it, so it
# reports the number actually checked instead of asserting over files that were
# never opened.
echo ""
echo "=== Check 2: @veritasacta/verify signatures ==="

# Published fixture key from fixtures/keys/README.md. The reference receipts
# carry their key inside the signed bytes; the verifier refuses to trust it
# (embedded_key_rejected, section 9.5) and verifies only against the key
# given here. A missing key and a tampered one are not the same finding
# (issue #13, finding 3; issue #21).
CONFORMANCE_KEY="${CONFORMANCE_KEY:-4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29}"

SIG_CHECKED=0
SIG_FAILED=0
for f in "$RECEIPTS_DIR"/*.json; do
    [ -e "$f" ] || continue
    SIG_CHECKED=$((SIG_CHECKED+1))
    # Exit 2 covers every undecidable outcome (no key resolved, an embedded
    # key refused, an unknown shape, malformed JSON), so the JSON verdict's
    # error code is what tells them apart. ERRORS.md in the verifier lists them.
    OUT="$(npx --yes @veritasacta/verify --key "$CONFORMANCE_KEY" "$f" --json 2>/dev/null)"
    RC=$?
    CODE="$(printf '%s' "$OUT" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("error") or "")
except Exception: print("")' 2>/dev/null)"
    case "$RC" in
        0) ;;
        1) fail "signature failed verification (${CODE:-tampered}): $(basename "$f")"; SIG_FAILED=$((SIG_FAILED+1)) ;;
        2) case "$CODE" in
               no_public_key|embedded_key_rejected) fail "no trusted key resolved ($CODE); set CONFORMANCE_KEY to the fixture key: $(basename "$f")" ;;
               unknown_format) fail "unrecognised receipt shape ($CODE); the verifier does not read this shape: $(basename "$f")" ;;
               *) fail "undecidable (${CODE:-no code}): $(basename "$f")" ;;
           esac; SIG_FAILED=$((SIG_FAILED+1)) ;;
        *) fail "verifier exited with unexpected code $RC on $(basename "$f")"; SIG_FAILED=$((SIG_FAILED+1)) ;;
    esac
done

if [ "$SIG_CHECKED" -eq 0 ]; then
    fail "no receipts to verify"
elif [ "$SIG_FAILED" -eq 0 ]; then
    pass "all $SIG_CHECKED signature(s) verify"
fi

# ----- Check 3: chain integrity + expected outcomes ---------------------------
# Previously this checked only that parent_receipt_hash was non-empty. It
# computed the expected hash and discarded it, so any constant string passed,
# and expected/chain.jsonl and the fixtures' expected_decision were read by no
# code at all. An implementation could ignore the policy, emit four correctly
# signed receipts with arbitrary decisions, and be reported conformant.
# Reported in #13.
echo ""
echo "=== Check 3: chain order, parent-hash linkage, expected outcomes ==="
python3 "$REPO_ROOT/conformance/check_chain.py" "$RECEIPTS_DIR" "$REPO_ROOT"
if [ "$?" -eq 0 ]; then
    pass "chain order, linkage, and expected outcomes"
else
    fail "chain order, linkage, and expected outcomes"
fi

# ----- Summary ----------------------------------------------------------------
echo ""
echo "─────────────────────────────────────────────"
echo "  $PASS passed, $FAIL failed"
echo "─────────────────────────────────────────────"
[ "$FAIL" -eq 0 ]
