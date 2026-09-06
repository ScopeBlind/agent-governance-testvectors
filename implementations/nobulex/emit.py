#!/usr/bin/env python3
"""
nobulex conformance driver.

Reads every fixture in fixtures/inputs/, evaluates it against
fixtures/policy/autoresearch-safe.cedar, and writes one signed receipt per
fixture to receipts/nobulex/.

Two properties this driver holds itself to, both of which are things issue #13
found the suite could not previously detect:

  1. It never reads `expected_decision`. Decisions come from evaluating the
     policy. A driver that reads the fixture's expected answer proves nothing,
     and until PR #14 the suite would have reported it conformant.

  2. It emits the `decision_receipt` shape that `@veritasacta/verify` accepts
     and that this repository's own aps-gateway-enforcement receipts use,
     rather than the v1 flat shape the schema described. That choice is the
     subject of #12 and was made at the maintainer's request.

Signature: Ed25519 (RFC 8032) over the RFC 8785 canonical bytes of the whole
envelope with `signature` removed, hex encoded, which is the convention the
aps-gateway-enforcement receipts use and which @veritasacta/verify accepts.

Key: derived from the shared conformance seed in fixtures/keys/README.md, so
every implementation signs under the same keypair. `kid` is the RFC 7638 JWK
thumbprint of the public key. The receipt carries no inline public key on
purpose: draft-farley-acta-signed-receipts says a verifier must not accept a
key transported inside the envelope unless it is independently anchored.
"""

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cedar_lite import parse, evaluate  # noqa: E402

SEED_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
POLICY_ID = "autoresearch-safe"
ISSUER = "nobulex:testvectors:driver"
ISSUED_AT = "2026-01-01T00:00:00Z"


def jcs(value) -> bytes:
    """RFC 8785 for the subset these receipts use: sorted keys, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def chain_canonical(receipt: dict) -> str:
    """The form conformance check 3 hashes for parent linkage.

    Kept byte-identical to that function on purpose: if this driver computed a
    different canonical form, every parent hash would mismatch and the failure
    would look like tampering rather than like disagreement about bytes.
    """
    return json.dumps(
        {k: v for k, v in receipt.items() if k not in ("signature", "public_key")},
        sort_keys=True,
        separators=(",", ":"),
    )


def load_signer():
    seed = bytes.fromhex(SEED_HEX)
    try:
        from nacl.signing import SigningKey
        sk = SigningKey(seed)
        return (lambda m: sk.sign(m).signature), sk.verify_key.encode()
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        raw = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return sk.sign, raw
    except ImportError:
        pass
    sys.stderr.write(
        "skip: need an Ed25519 library. Install either:\n"
        "    pip install pynacl\n"
        "    pip install cryptography\n")
    raise SystemExit(77)


def jwk_thumbprint(public_key: bytes) -> str:
    """RFC 7638 thumbprint of the Ed25519 JWK, which is how kid is derived here."""
    jwk = {"crv": "Ed25519", "kty": "OKP",
           "x": base64.urlsafe_b64encode(public_key).decode().rstrip("=")}
    return base64.urlsafe_b64encode(
        hashlib.sha256(jcs(jwk)).digest()).decode().rstrip("=")


def main() -> int:
    here = Path(__file__).resolve().parent
    repo = here.parent.parent
    fixtures = sorted((repo / "fixtures" / "inputs").glob("*.json"))
    if not fixtures:
        sys.stderr.write("error: no fixtures found\n")
        return 1

    out = repo / "receipts" / "nobulex"
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.glob("*.json"):
        stale.unlink()

    rules = parse((repo / "fixtures" / "policy" / (POLICY_ID + ".cedar")).read_text())
    sign, public_key = load_signer()
    kid = jwk_thumbprint(public_key)

    parent_hash = None
    written = 0
    for path in fixtures:
        fixture = json.loads(path.read_text())
        # Removed before use so a future edit cannot quietly start depending on it.
        fixture.pop("expected_decision", None)

        decision = evaluate(rules, fixture["tool_name"], fixture.get("context", {}))

        receipt = {
            "v": 2,
            "type": "decision_receipt",
            "algorithm": "ed25519",
            "kid": kid,
            "issuer": ISSUER,
            "issued_at": ISSUED_AT,
            "sequence": fixture["sequence"],
            "parent_receipt_hash": parent_hash,
            "payload": {
                "decision": decision,
                "tool_name": fixture["tool_name"],
                "policy_id": POLICY_ID,
                "session_id": fixture.get("session_id"),
                "input_hash": "sha256:" + hashlib.sha256(
                    jcs(fixture.get("tool_input", {}))).hexdigest(),
                "context": fixture.get("context", {}),
            },
        }
        receipt["signature"] = sign(jcs(
            {k: v for k, v in receipt.items() if k != "signature"})).hex()

        name = out / ("receipt-%04d.json" % fixture["sequence"])
        name.write_text(json.dumps(receipt, indent=2) + "\n")
        parent_hash = hashlib.sha256(chain_canonical(receipt).encode()).hexdigest()
        written += 1

    print("nobulex: %d receipts in %s" % (written, out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
