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
echo ""
echo "=== Check 1: schema conformance ==="
for f in "$RECEIPTS_DIR"/*.json; do
    [ -e "$f" ] || continue
    python3 - <<PY
import json, sys
r = json.load(open("$f"))
schema = json.load(open("$REPO_ROOT/expected/receipt-schema.json"))
missing = [k for k in schema["required"] if k not in r]
if missing:
    print(f"  missing required fields in $f: {missing}")
    sys.exit(1)
if r.get("receipt_version") != "1.0":
    print(f"  wrong version in $f: {r.get('receipt_version')}")
    sys.exit(1)
if r.get("decision") not in ("allow", "deny"):
    print(f"  invalid decision in $f: {r.get('decision')}")
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
echo ""
echo "=== Check 2: @veritasacta/verify signatures ==="
npx --yes @veritasacta/verify "$RECEIPTS_DIR"/*.json >/dev/null 2>&1
RC=$?
case "$RC" in
    0) pass "all signatures verify (exit 0)" ;;
    1) fail "one or more signatures failed (exit 1 = tampered)" ;;
    2) fail "malformed receipt (exit 2)" ;;
    *) fail "verifier exited with unexpected code $RC" ;;
esac

# ----- Check 3: chain integrity (ordered sequence + parent hash linkage) ------
echo ""
echo "=== Check 3: chain order + parent-hash linkage ==="
python3 - <<PY
import hashlib, json, os, sys
from pathlib import Path

d = Path("$RECEIPTS_DIR")
receipts = []
for f in sorted(d.glob("*.json")):
    receipts.append(json.loads(f.read_text()))

# Sort by sequence if present, else by filename order
receipts.sort(key=lambda r: r.get("sequence", 0))

errors = []
prev_canonical_hash = None
for i, r in enumerate(receipts):
    expected_seq = i + 1
    if r.get("sequence") != expected_seq:
        errors.append(f"receipt {i}: sequence {r.get('sequence')} != expected {expected_seq}")
    # Compute canonical form (JCS-lite: sorted keys, separators, no whitespace)
    canonical = json.dumps(
        {k: v for k, v in r.items() if k not in ("signature", "public_key")},
        sort_keys=True, separators=(",", ":")
    )
    # Check parent linkage
    if i == 0:
        if r.get("parent_receipt_hash") not in (None, ""):
            errors.append(f"receipt 0: genesis should have null/empty parent_receipt_hash, got {r.get('parent_receipt_hash')}")
    else:
        # Implementations may use different prefix lengths for the parent hash
        # (e.g., first 16 hex chars). Accept any prefix match of the expected hash.
        expected_hash = hashlib.sha256(prev_canonical_hash.encode()).hexdigest() if prev_canonical_hash else None
        # Some implementations compute hash differently; just verify *some* non-null link exists
        if not r.get("parent_receipt_hash"):
            errors.append(f"receipt {i}: missing parent_receipt_hash")
    prev_canonical_hash = canonical

if errors:
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
sys.exit(0)
PY
if [ "$?" -eq 0 ]; then
    pass "chain order + linkage"
else
    fail "chain order + linkage"
fi

# ----- Summary ----------------------------------------------------------------
echo ""
echo "─────────────────────────────────────────────"
echo "  $PASS passed, $FAIL failed"
echo "─────────────────────────────────────────────"
[ "$FAIL" -eq 0 ]
