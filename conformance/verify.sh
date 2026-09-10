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
# expected/receipt-schema.json is a oneOf over the four shapes actually in
# use here: the Acta 2.1 envelope, decision_receipt, the v2 envelope, and v1
# flat. This is a lightweight field-level test that does not need a JSON
# Schema validator dependency; keep it in step with the schema.
echo ""
echo "=== Check 1: schema conformance (one of four shapes) ==="
for f in "$RECEIPTS_DIR"/*.json; do
    [ -e "$f" ] || continue
    python3 - <<PY
import json, sys
r = json.load(open("$f"))

# Four shapes are in use in this repository. Only the Acta 2.1 envelope is
# the shape draft-farley-acta-signed-receipts-03 specifies; the others are
# recorded because real implementations emit them. This is a field-level
# test, not a JSON Schema validator, so keep it in step with
# expected/receipt-schema.json (issue #13, finding 4).

# Acta 2.1 envelope (protect-mcp 0.12+): {payload, signature:{alg,kid,sig}}.
# No top-level pubkey; the key is named by signature.kid.
def is_acta_envelope(r):
    return (
        isinstance(r, dict)
        and isinstance(r.get("payload"), dict)
        and isinstance(r.get("signature"), dict)
        and all(k in r["signature"] for k in ("alg", "kid", "sig"))
        and "decision" in r["payload"]
    )

# decision_receipt (APS gateway, nobulex): a payload member, a bare hex
# signature, and algorithm/kid/issuer at the top level. Not the 2.1 envelope.
# Shape test contributed in #12.
def is_decision_receipt(r):
    return (
        isinstance(r, dict)
        and r.get("type") == "decision_receipt"
        and all(k in r for k in ("v", "algorithm", "kid", "issuer",
                                 "issued_at", "payload", "signature"))
        and isinstance(r.get("payload"), dict)
        and "decision" in r["payload"]
    )

# v2 envelope (sb-runtime): payload/signature/pubkey wrapper
def is_v2(r):
    return (
        isinstance(r, dict)
        and "payload" in r
        and "signature" in r
        and "pubkey" in r
        and isinstance(r["payload"], dict)
        and r["payload"].get("type", "").startswith("scopeblind.receipt.")
        and "decision" in r["payload"]
        and "action" in r["payload"]
    )

# v1 flat (protect-mcp-adk): required top-level fields
v1_required = ["receipt_id", "receipt_version", "tool_name", "decision",
               "policy_id", "timestamp", "public_key", "signature"]

shape = ("actaEnvelope" if is_acta_envelope(r) else
         "decision_receipt" if is_decision_receipt(r) else
         "v2 envelope" if is_v2(r) else None)
if shape:
    d = r["payload"].get("decision")
    if d not in ("allow", "deny"):
        print(f"  {shape} invalid decision in $f: {d}")
        sys.exit(1)
    sys.exit(0)

missing = [k for k in v1_required if k not in r]
if missing:
    print(f"  $f matches none of actaEnvelope, decision_receipt, v2 envelope, "
          f"v1 flat (missing {missing})")
    sys.exit(1)
if r.get("receipt_version") != "1.0":
    print(f"  v1 wrong version in $f: {r.get('receipt_version')}")
    sys.exit(1)
if r.get("decision") not in ("allow", "deny"):
    print(f"  v1 invalid decision in $f: {r.get('decision')}")
    sys.exit(1)
sys.exit(0)
PY
    if [ "$?" -eq 0 ]; then
        pass "schema ok: $(basename "$f")"
    else
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

# Published fixture key from fixtures/keys/README.md. Receipts here carry `kid`
# rather than an inline public key, so without this the verifier exits with
# no_public_key and that gets reported as a failed signature — a missing key and
# a tampered one are not the same finding. (Issue #13, finding 3.)
CONFORMANCE_KEY="${CONFORMANCE_KEY:-4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29}"

SIG_CHECKED=0
SIG_FAILED=0
for f in "$RECEIPTS_DIR"/*.json; do
    [ -e "$f" ] || continue
    SIG_CHECKED=$((SIG_CHECKED+1))
    npx --yes @veritasacta/verify --key "$CONFORMANCE_KEY" "$f" >/dev/null 2>&1
    RC=$?
    case "$RC" in
        0) ;;
        1) fail "signature failed verification: $(basename "$f")"; SIG_FAILED=$((SIG_FAILED+1)) ;;
        2) fail "malformed or unrecognised receipt: $(basename "$f")"; SIG_FAILED=$((SIG_FAILED+1)) ;;
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
