#!/usr/bin/env bash
# APS governance hook conformance driver.
#
# Reads fixtures/inputs/*.json in sequence, evaluates each against
# fixtures/policy/autoresearch-safe.cedar via Cedar (cedarpy bindings, the
# official Python wrapper around the Rust cedar-policy crate), and emits
# v2 structured-envelope receipts signed with Ed25519 using the fixture
# seed.
#
# Output: receipts/aps-governance-hook/{name}.json
# Exit 0 on success, 77 if dependencies missing (matches protect-mcp pattern).

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/fixtures"
OUT="$REPO_ROOT/receipts/aps-governance-hook"
mkdir -p "$OUT"

command -v python3 >/dev/null 2>&1 || { echo "skip: python3 required"; exit 77; }

# cedarpy and cryptography are the two Python-side dependencies. cedarpy
# wraps the official Rust cedar-policy crate (NOT a re-implementation);
# cryptography provides RFC 8032 Ed25519.
python3 - <<'PYPROBE' 2>/dev/null
import cedarpy  # noqa: F401
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
PYPROBE
if [ "$?" -ne 0 ]; then
    echo "skip: python3 packages 'cedarpy' and 'cryptography' required (pip install cedarpy cryptography)"
    exit 77
fi

POLICY="$FIXTURES/policy/autoresearch-safe.cedar"
SEED_HEX="0000000000000000000000000000000000000000000000000000000000000001"
# payload.prev_hash for the first receipt in the chain (cryptographic
# chain genesis). Top-level `parent_receipt_hash` is separately set to
# null for the first receipt so conformance/verify.sh's check 3 passes.
PAYLOAD_GENESIS_HASH="sha256:0000000000000000000000000000000000000000000000000000000000000000"

# Single Python process handles all fixtures: keeps the Cedar engine warm
# and threads the chain hash forward across the four receipts.
REPO_ROOT="$REPO_ROOT" \
FIXTURES="$FIXTURES" \
OUT="$OUT" \
POLICY_PATH="$POLICY" \
SEED_HEX="$SEED_HEX" \
PAYLOAD_GENESIS_HASH="$PAYLOAD_GENESIS_HASH" \
python3 <<'PYDRIVE'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import cedarpy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FIXTURES = Path(os.environ["FIXTURES"])
OUT = Path(os.environ["OUT"])
POLICY_PATH = Path(os.environ["POLICY_PATH"])
SEED_HEX = os.environ["SEED_HEX"]
PAYLOAD_GENESIS_HASH = os.environ["PAYLOAD_GENESIS_HASH"]

# ---- Ed25519 key material from the fixture seed ------------------------
sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))
pk_hex = sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()

# ---- Policy text: rewrite `context.X in [ ... ]` to `[ ... ].contains(...)`
# Cedar 4.x strict typing requires `in` LHS to be an entity; the shared
# ScopeBlind policy uses the older Cedar idiom `string in [strings]`.
# `.contains()` is the Cedar-native set-membership operator. This is a
# text rewrite, not a re-implementation of Cedar evaluation — cedarpy
# (the official Rust engine) still does the actual authorize call.
policy_raw = POLICY_PATH.read_text()
policy = re.sub(
    r"(\bcontext\.[A-Za-z_][A-Za-z0-9_]*)\s+in\s+(\[[^\]]*\])",
    lambda m: f"{m.group(2)}.contains({m.group(1)})",
    policy_raw,
)

# Policy digest for receipt traceability — computed over the ORIGINAL
# on-disk policy text so the digest matches what other implementations
# would compute from the shared fixture.
policy_digest = "sha256:" + hashlib.sha256(policy_raw.encode("utf-8")).hexdigest()

# ---- JCS canonicalization (RFC 8785) -----------------------------------
# Equivalent to @veritasacta/artifacts' canonicalize() for the field types
# present in these receipts: strings, integers, booleans, nulls, arrays,
# objects with ASCII-only keys. JCS number edge cases (exponent
# normalization, trailing-zero stripping for fractional numbers) do not
# arise in ScopeBlind test vectors.
def jcs(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---- Cedar evaluation -------------------------------------------------
def evaluate(tool_name: str, context: dict) -> str:
    request = {
        "principal": 'User::"agent"',
        "action":    f'Action::"{tool_name}"',
        "resource":  'Resource::"tool"',
        "context":   context,
    }
    result = cedarpy.is_authorized(request, policy, [])
    return "allow" if str(result.decision).endswith("Allow") else "deny"

# ---- Build the chain ---------------------------------------------------
input_files = sorted(FIXTURES.joinpath("inputs").glob("*.json"))
if not input_files:
    print("error: no fixture inputs found", file=sys.stderr)
    sys.exit(1)

# `prev_hash_payload` is what goes INSIDE payload.prev_hash (chained via
# all-zeros for genesis). `prev_hash_top` is what goes at top-level
# `parent_receipt_hash` (null for genesis, per verify.sh check 3).
prev_hash_payload = PAYLOAD_GENESIS_HASH
prev_hash_top = None
written = 0

for idx, input_file in enumerate(input_files, start=1):
    name = input_file.stem
    inp = json.loads(input_file.read_text())

    tool_name = inp["tool_name"]
    context = inp.get("context", {})
    sequence = inp.get("sequence", idx)

    decision = evaluate(tool_name, context)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "type":       "scopeblind.receipt.v1",
        "decision":   decision,
        "action":     {"kind": "tool", "target": tool_name},
        "policy_id":  "autoresearch-safe",
        "sequence":   sequence,
        "prev_hash":  prev_hash_payload,
        "timestamp":  timestamp,
        "context":    context,
        # Embedded so @veritasacta/verify's key-lookup path
        # (artifact.payload.public_key) finds it without --key.
        "public_key": pk_hex,
    }

    # Everything that WILL end up in the written JSON except `signature`.
    # @veritasacta/verify strips `signature` and hashes the canonical
    # form of the rest; signing that exact object makes verification
    # succeed without touching the verifier.
    to_sign = {
        "payload":             payload,
        "pubkey":              pk_hex,
        "sequence":            sequence,
        "parent_receipt_hash": prev_hash_top,
        "policy_digest":       policy_digest,
    }

    signed_bytes = jcs(to_sign)
    signature = sk.sign(signed_bytes).hex()

    envelope = dict(to_sign, signature=signature)

    out_path = OUT / f"{name}.json"
    out_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False))
    written += 1

    # Chain linkage:
    #   payload.prev_hash (next)  = sha256 of JCS-canonical full envelope
    #   parent_receipt_hash (next) = same (for verify.sh check 3)
    next_hash = "sha256:" + sha256_hex(jcs(envelope))
    prev_hash_payload = next_hash
    prev_hash_top = next_hash

print(f"aps-governance-hook: {written} receipts in {OUT}")
PYDRIVE
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "aps-governance-hook driver exited $RC"
    exit "$RC"
fi

INPUT_COUNT="$(ls "$FIXTURES/inputs"/*.json 2>/dev/null | wc -l | tr -d ' ')"
OUTPUT_COUNT="$(ls "$OUT"/*.json 2>/dev/null | wc -l | tr -d ' ')"
if [ "$OUTPUT_COUNT" -ne "$INPUT_COUNT" ]; then
    echo "aps-governance-hook: produced $OUTPUT_COUNT receipts, expected $INPUT_COUNT"
    exit 1
fi

exit 0
