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
from cedar_lite import parse, evaluate, PolicyTypeError  # noqa: E402

SEED_HEX = "0000000000000000000000000000000000000000000000000000000000000001"
POLICY_ID = "autoresearch-safe"
ISSUER = "nobulex:testvectors:driver"
ISSUED_AT = "2026-01-01T00:00:00Z"


def jcs(value) -> bytes:
    """RFC 8785 for the subset these receipts use: sorted keys, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def chain_link(receipt: dict) -> str:
    """The previousReceiptHash the next receipt carries.

    draft-farley-acta-signed-receipts-03 section 6.7:

        previousReceiptHash = "sha256:" + lowercase-hex( SHA-256( JCS(receipt) ) )

    Three things this gets right that the earlier form did not, and each was a
    live convention in some implementation in this repository before 6.7
    settled the question.

    The preimage is the ENTIRE signed receipt, signature member included. The
    earlier form stripped signature and public_key, so re-signing an identical
    payload produced an identical link and a key rotation left no trace in the
    chain. Including the signature is what makes the link cover the act of
    signing rather than only the thing signed.

    The digest carries its sha256: prefix, so it is self-describing and matches
    how policy_digest and source.ref are written elsewhere in the draft.

    And it is computed with the same jcs() used for the signature preimage
    rather than a second json.dumps carrying its own arguments. Two
    canonicalizations that agree today are two that can drift, and a drift here
    surfaces as every link mismatching, which reads as tampering rather than as
    a disagreement about bytes.
    """
    return "sha256:" + hashlib.sha256(jcs(receipt)).hexdigest()


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

    # A policy the reference engine refuses is not something to emit receipts
    # against. 77 is this suite's skip convention, so the summary says skipped
    # rather than showing a traceback that would read as a defect in this
    # driver. It is the corpus that is invalid here, and saying which is more
    # useful than either crashing or quietly evaluating it anyway.
    try:
        rules = parse(
            (repo / "fixtures" / "policy" / (POLICY_ID + ".cedar")).read_text())
    except PolicyTypeError as exc:
        sys.stderr.write(
            "skip: the fixture policy is not valid Cedar, so no decision is "
            "derived from it.\n  %s\n"
            "  Corrected upstream in #17. This driver refuses what cedar-wasm "
            "refuses rather than accepting a policy the reference engine will "
            "not run.\n" % exc)
        return 77
    sign, public_key = load_signer()
    kid = jwk_thumbprint(public_key)

    parent_hash = None
    written = 0
    for path in fixtures:
        fixture = json.loads(path.read_text())
        # Removed before use so a future edit cannot quietly start depending on it.
        fixture.pop("expected_decision", None)

        decision = evaluate(rules, fixture["tool_name"], fixture.get("context", {}))

        payload = {
            "decision": decision,
            "tool_name": fixture["tool_name"],
            "policy_id": POLICY_ID,
            "session_id": fixture.get("session_id"),
            "input_hash": "sha256:" + hashlib.sha256(
                jcs(fixture.get("tool_input", {}))).hexdigest(),
            "context": fixture.get("context", {}),
        }
        # Section 2.2 places the member inside payload, and requires the first
        # receipt to OMIT it rather than carry null or "". Those are not
        # equivalent: either one changes the JCS bytes and therefore the
        # signature, so a genesis receipt written with an explicit null does
        # not verify against one written without the member.
        if parent_hash is not None:
            payload["previousReceiptHash"] = parent_hash

        receipt = {
            "v": 2,
            "type": "decision_receipt",
            "algorithm": "ed25519",
            "kid": kid,
            "issuer": ISSUER,
            "issued_at": ISSUED_AT,
            "sequence": fixture["sequence"],
            "payload": payload,
        }
        receipt["signature"] = sign(jcs(
            {k: v for k, v in receipt.items() if k != "signature"})).hex()

        name = out / ("receipt-%04d.json" % fixture["sequence"])
        name.write_text(json.dumps(receipt, indent=2) + "\n")
        # Computed from the receipt AFTER its signature is attached, because
        # 6.7 makes the signature part of the preimage.
        parent_hash = chain_link(receipt)
        written += 1

    print("nobulex: %d receipts in %s" % (written, out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
