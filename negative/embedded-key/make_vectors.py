#!/usr/bin/env python3
"""Receipts that carry their own verification key, one per accepted shape.

Issue #21. Section 9.5 of draft-farley-acta-signed-receipts-03: a key carried
inside the receipt is signer-controlled, so a signature that verifies under it
establishes only that whoever wrote the receipt also wrote the signature.

Carrying the key is not itself the violation, and these vectors are not
malformed. The Acta envelope may name its key, the reference receipts in
receipts/protect-mcp/ carry one inside the signed bytes, and the schema
permits it on both accepted shapes. What 9.5 forbids is TRUSTING it. So each
file here is a well-formed, schema-valid receipt whose signature verifies
perfectly under the key it supplies, and the only correct response to it is to
refuse to resolve that key and say so.

Two shapes, because those are the two the published verifier reads. The v1
flat and v2 envelope vectors from the first draft of this directory are gone:
main now marks both not-accepted in the schema, and a vector for a shape
nothing emits and nothing verifies tests nothing.

THREE KEYS, AND WHY EACH EXISTS

  adversary  seed ...ff   signs these receipts and is embedded in them
  bystander  seed ...02   a valid key that did NOT sign them
  conformance seed ...01  the published fixture key, never used here

The bystander key is the one that makes this suite mean something. With no key
the verifier must return the undecidable code rather than a verdict. Handed a
key that is valid but wrong, it must return a real failure, exit 1, because
that is a check that ran and failed. Without that second case a verifier could
pass by refusing everything.

    python3 negative/embedded-key/make_vectors.py
"""
import base64
import hashlib
import json
import pathlib

try:
    from nacl.signing import SigningKey
except ImportError:
    raise SystemExit(
        "needs pynacl: python3 -m pip install pynacl\n"
        "These vectors carry real signatures. A placeholder would make a "
        "verifier refuse them for the wrong reason, which is the failure this "
        "directory exists to rule out.")

HERE = pathlib.Path(__file__).parent
SCHEMA_PATH = HERE.parent.parent / "expected" / "receipt-schema.json"

ADVERSARY_SEED = bytes.fromhex("00" * 31 + "ff")
BYSTANDER_SEED = bytes.fromhex("00" * 31 + "02")


def jcs(value):
    """RFC 8785 over the subset these receipts use: sorted keys, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


adversary = SigningKey(ADVERSARY_SEED)
ADVERSARY_HEX = bytes(adversary.verify_key).hex()
BYSTANDER_HEX = bytes(SigningKey(BYSTANDER_SEED).verify_key).hex()

JWK = {"crv": "Ed25519", "kty": "OKP", "x": b64u(bytes(adversary.verify_key))}
KID = b64u(hashlib.sha256(jcs(JWK)).digest())


def acta_envelope():
    """Signature covers jcs(payload).

    Established empirically against receipts/protect-mcp/001-allow-read.json,
    whose existing signature verifies over jcs(payload) and over none of the
    alternatives tried. Modelled on that file so the only thing separating
    this from a conformant receipt is which key signed it.
    """
    payload = {
        "type": "protectmcp:decision",
        "tool_name": "Read",
        "decision": "allow",
        "reason": "post_execution_receipt",
        "policy_digest": "none",
        "scope": "negative-embedded-key",
        "mode": "enforce",
        "request_id": "negative-embedded-key",
        "spec": "draft-farley-acta-signed-receipts-03",
        "issuer_certification": "self-signed",
        # The key this receipt's signature verifies under, inside the signed
        # bytes. A verifier that resolves it here checks the signer against
        # the signer.
        "public_key": ADVERSARY_HEX,
        "issuer_name": "protect-mcp",
        "issued_at": "2026-01-01T00:00:00Z",
        "issuer_id": "conformance",
    }
    return {
        "payload": payload,
        "signature": {
            "alg": "EdDSA",
            "kid": "conformance",
            "sig": adversary.sign(jcs(payload)).signature.hex(),
        },
    }


def decision_receipt():
    """Signature covers jcs(receipt minus "signature").

    From implementations/nobulex/emit.py, and corroborated by
    aps-gateway-enforcement/2-external-verification/canonical.txt, whose bytes
    are exactly the sorted receipt minus the signature member. So the top
    level public_key below is provably inside the signed bytes rather than
    merely alongside them.
    """
    receipt = {
        "v": 2,
        "type": "decision_receipt",
        "algorithm": "ed25519",
        "kid": KID,
        "issuer": "aps:gateway:test",
        "issued_at": "2026-01-01T00:00:00Z",
        "payload": {
            "decision": "allow",
            "request_id": "req-negative-embedded-key",
            "tool": "http.get",
            "policy_id": "autoresearch-safe",
            "reason_code": "policy_match",
        },
        "public_key": ADVERSARY_HEX,
    }
    receipt["signature"] = adversary.sign(jcs(receipt)).signature.hex()
    return receipt


SHAPES = [
    ("acta-envelope.json", acta_envelope,
     "`payload.public_key`, signed over jcs(payload)"),
    ("decision-receipt.json", decision_receipt,
     "top level `public_key`, inside the signed bytes"),
]


def validate(built):
    """Refuse to write a vector the repository's own schema rejects.

    The first version of this directory did not do this. Two of its four
    vectors were built against the old hand-rolled check 1, which never tested
    receipt_id and accepted a bare string where an object was required, so
    they passed it and failed the schema. Their refusal by the verifier was
    then read as evidence about the verifier. A vector refused for being
    malformed has tested the schema and not section 9.5.
    """
    try:
        import jsonschema
    except ImportError:
        print("WARNING: jsonschema not installed, vectors NOT validated.\n"
              "         python3 -m pip install jsonschema")
        return
    schema = json.load(open(SCHEMA_PATH))
    bad = []
    for name, receipt in built:
        try:
            jsonschema.validate(receipt, schema)
        except jsonschema.ValidationError as exc:
            bad.append((name, exc.message))
    if bad:
        for name, msg in bad:
            print("SCHEMA FAIL %s: %s" % (name, msg))
        raise SystemExit("refusing to write %d malformed vector(s)." % len(bad))
    print("%d vectors validate against %s" % (len(built), SCHEMA_PATH.name))


def main():
    built = [(name, build()) for name, build, _ in SHAPES]
    validate(built)
    for name, receipt in built:
        (HERE / name).write_text(json.dumps(receipt, indent=2) + "\n")

    (HERE / "KEYS.md").write_text(
        "# Keys used by these vectors\n\n"
        "Derived from fixed seeds so anyone can rebuild them.\n\n"
        "| role | seed | public key |\n|---|---|---|\n"
        "| adversary, signs and is embedded | `00..ff` | `%s` |\n"
        "| bystander, valid but did not sign | `00..02` | `%s` |\n"
        "| conformance, unused here | `00..01` | `4cb5abf6...` |\n\n"
        "The adversary key is deliberately not the conformance key. A "
        "verifier that happens to have the fixture key loaded must still "
        "refuse these, and sharing the key would let it pass for a reason "
        "that has nothing to do with section 9.5.\n" % (ADVERSARY_HEX, BYSTANDER_HEX))

    print("wrote %d vectors to %s" % (len(built), HERE))
    for name, _, note in SHAPES:
        print("  %-22s %s" % (name, note))
    print("\nadversary (embedded): %s" % ADVERSARY_HEX)
    print("bystander (wrong key): %s" % BYSTANDER_HEX)


if __name__ == "__main__":
    main()
