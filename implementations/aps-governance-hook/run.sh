#!/usr/bin/env bash
# APS governance hook conformance driver.
#
# Reads fixtures/inputs/*.json in sequence, evaluates each against
# fixtures/policy/autoresearch-safe.cedar via Cedar (cedarpy bindings, the
# official Python wrapper around the Rust cedar-policy crate), and emits
# ACTA v2 structured-envelope receipts (draft-farley-acta-signed-receipts /
# @veritasacta/artifacts) signed with Ed25519 using the fixture seed.
#
# Signing and canonicalization reuse the Agent Passport System SDK
# primitives (agent_passport.canonicalize_jcs, agent_passport.sign,
# agent_passport.public_key_from_private). No crypto is reimplemented here;
# the JCS bytes are byte-identical to @veritasacta/artifacts' canonicalize.
#
# Output:
#   receipts/aps-governance-hook/{name}.json   ACTA v2 receipts (one per input)
#   receipts/aps-governance-hook/_keys/jwks.json  signing key as a JWK, keyed by kid
#
# The verifier resolves the key by `kid` from the JWKS (no embedded key in
# the receipt). Exit 0 on success, 77 if dependencies missing.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/fixtures"
OUT="$REPO_ROOT/receipts/aps-governance-hook"
mkdir -p "$OUT/_keys"

command -v python3 >/dev/null 2>&1 || { echo "skip: python3 required"; exit 77; }

# cedarpy wraps the official Rust cedar-policy crate (NOT a re-implementation).
# agent_passport (the APS Python SDK) provides RFC 8032 Ed25519 signing and
# RFC 8785 JCS canonicalization, reused here so the receipt bytes match the
# ACTA verifier without hand-rolling crypto.
python3 - <<'PYPROBE' 2>/dev/null
import cedarpy  # noqa: F401
import agent_passport  # noqa: F401
PYPROBE
if [ "$?" -ne 0 ]; then
    echo "skip: python3 packages 'cedarpy' and 'agent-passport-system' required (pip install cedarpy agent-passport-system)"
    exit 77
fi

POLICY="$FIXTURES/policy/autoresearch-safe.cedar"
SEED_HEX="0000000000000000000000000000000000000000000000000000000000000001"
# payload.previousReceiptHash links each receipt to the prior receipt's
# JCS-canonical hash (draft-farley-acta-signed-receipts-03 section 6.7). The
# first receipt OMITS the member entirely per section 2.2: null and "" produce
# different JCS bytes and therefore a different signature.

REPO_ROOT="$REPO_ROOT" \
FIXTURES="$FIXTURES" \
OUT="$OUT" \
POLICY_PATH="$POLICY" \
SEED_HEX="$SEED_HEX" \
python3 <<'PYDRIVE'
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import cedarpy
import agent_passport as ap

FIXTURES = Path(os.environ["FIXTURES"])
OUT = Path(os.environ["OUT"])
POLICY_PATH = Path(os.environ["POLICY_PATH"])
SEED_HEX = os.environ["SEED_HEX"]

# ---- Ed25519 key material from the fixture seed (APS SDK) --------------
pk_hex = ap.public_key_from_private(SEED_HEX)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# ---- kid: RFC 7638 JWK thumbprint of the Ed25519 public key -----------
# kid = base64url(SHA-256({"crv":"Ed25519","kty":"OKP","x":"<b64url(pubkey)>"}))
# The JSON input is already in RFC 7638 lexicographic member order.
x_b64url = b64url(bytes.fromhex(pk_hex))
_thumb_input = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % x_b64url
kid = b64url(hashlib.sha256(_thumb_input.encode("utf-8")).digest())

# ---- Policy text: used exactly as it is on disk ----------------------
# An earlier revision of this driver rewrote `context.X in [ ... ]` into
# `[ ... ].contains(...)` before evaluating, because the fixture policy used
# an idiom Cedar rejects. That made the driver evaluate a policy no other
# implementation held, and it hid the defect instead of reporting it. The
# fixture is valid Cedar as of #17, and the text is now evaluated unmodified.
policy = POLICY_PATH.read_text()

# Policy digest over the on-disk policy text, which is also the text evaluated.
policy_digest = "sha256:" + hashlib.sha256(policy.encode("utf-8")).hexdigest()


# ---- JCS canonicalization + signing (APS SDK, reused) ------------------
def jcs_bytes(obj) -> bytes:
    # agent_passport.canonicalize_jcs is RFC 8785 JCS, byte-identical to
    # @veritasacta/artifacts' canonicalize for these field types.
    return ap.canonicalize_jcs(obj).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sign_envelope(envelope_without_sig: dict) -> str:
    # ACTA signing: sign the JCS-canonical envelope with the signature field
    # absent. agent_passport.sign returns a hex Ed25519 signature.
    canonical = ap.canonicalize_jcs(envelope_without_sig)
    return ap.sign(canonical, SEED_HEX)


# ---- Cedar evaluation -------------------------------------------------
def evaluate(tool_name: str, context: dict) -> str:
    request = {
        "principal": 'User::"agent"',
        "action":    f'Action::"{tool_name}"',
        "resource":  'Resource::"tool"',
        "context":   context,
    }
    result = cedarpy.is_authorized(request, policy, [])
    # Cedar SKIPS a policy that errors during evaluation and returns Deny, with
    # the error only in diagnostics. A driver that reads `decision` alone cannot
    # tell "the forbid clause denied this" from "no clause evaluated at all", so
    # an unevaluated policy reports as a correct deny. Treat any diagnostic
    # error as a driver failure rather than a decision.
    errors = list(getattr(result.diagnostics, "errors", []) or [])
    if errors:
        raise RuntimeError(
            "cedar reported evaluation errors for %s; the decision does not rest "
            "on the policy: %s" % (tool_name, "; ".join(errors))
        )
    return "allow" if str(result.decision).endswith("Allow") else "deny"


# ---- Build the chain ---------------------------------------------------
input_files = sorted(FIXTURES.joinpath("inputs").glob("*.json"))
if not input_files:
    print("error: no fixture inputs found", file=sys.stderr)
    sys.exit(1)

prev_hash = None  # chain genesis: the member is omitted, not null
written = 0

for idx, input_file in enumerate(input_files, start=1):
    name = input_file.stem
    inp = json.loads(input_file.read_text())

    tool_name = inp["tool_name"]
    context = inp.get("context", {})
    sequence = inp.get("sequence", idx)

    decision = evaluate(tool_name, context)
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ACTA v2 decision_receipt payload. Section 2.2 places the chain link
    # inside payload under the name previousReceiptHash.
    payload = {
        "decision":      decision,
        "policy_id":     "autoresearch-safe",
        "policy_digest": policy_digest,
        "scope":         "autoresearch-safe",
        "tool":          tool_name,
        "sequence":      sequence,
        "context":       context,
    }
    # Genesis omits the member entirely rather than carrying null.
    if prev_hash is not None:
        payload["previousReceiptHash"] = prev_hash

    # ACTA v2 structured envelope. No embedded key: the verifier resolves the
    # public key by `kid` from _keys/jwks.json.
    envelope = {
        "v":          2,
        "type":       "decision_receipt",
        "algorithm":  "ed25519",
        "kid":        kid,
        "issuer":     "aps:governance-hook",
        "issued_at":  issued_at,
        "payload":    payload,
        # Sequence is surfaced at top level for the chain-order check. The
        # chain link is NOT: section 2.2 puts it in payload, once.
        "sequence":   sequence,
    }

    envelope["signature"] = sign_envelope(envelope)

    out_path = OUT / f"{name}.json"
    out_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False))
    written += 1

    # Next link: hash of the JCS-canonical full envelope (signature included).
    prev_hash = "sha256:" + sha256_hex(jcs_bytes(envelope))

# ---- Emit the signing key as a JWK, keyed by kid ----------------------
# The verifier path (kid + JWKS / signing_keys) reads this; the receipts
# carry no embedded key.
jwks = {
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": kid,
            "x":   x_b64url,
            "use": "sig",
            "alg": "EdDSA",
        }
    ]
}
(OUT / "_keys" / "jwks.json").write_text(json.dumps(jwks, indent=2) + "\n")

print(f"aps-governance-hook: {written} ACTA v2 receipts in {OUT} (kid {kid})")
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
