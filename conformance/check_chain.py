#!/usr/bin/env python3
"""Chain-linkage conformance check.

The previous check computed an expected hash and then discarded it, accepting
any non-empty link. That passed every receipt set it was ever given, including
sets whose links were unrelated to their contents.

This checks the rule in draft-farley-acta-signed-receipts, and when a set does
not satisfy it, identifies which convention the producer actually used instead
of failing with "mismatch". The conventions below are all in use across the
implementations in this repository, which is the finding this script exists to
surface.

Draft rule (Chain Hash Scope):
    previousReceiptHash = lowercase-hex( SHA-256( JCS(entire signed receipt) ) )
  The signature is INCLUDED in the preimage, so re-signing an identical
  payload yields a distinct link. Genesis omits the member entirely.

Usage: check_chain.py <receipts-dir>
Exit:  0 conformant, 1 non-conformant, 2 usage/IO error.
"""
import hashlib
import json
import sys
from base64 import urlsafe_b64encode
from pathlib import Path

FIELD_NAMES = ("previousReceiptHash", "previous_receipt_hash", "parent_receipt_hash")


def jcs(obj) -> bytes:
    """RFC 8785 canonical form, ASCII-key subset (sufficient for these vectors)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _hex(b: bytes) -> str:
    return b.hex()


def _prefixed_hex(b: bytes) -> str:
    return "sha256:" + b.hex()


def _b64url(b: bytes) -> str:
    return urlsafe_b64encode(b).decode().rstrip("=")


# (name, preimage selector, encoder). The first entry is the draft's rule.
CONVENTIONS = [
    ("draft: hex(SHA256(JCS(receipt)))", lambda r, p: r, _hex),
    ("sdk-js/sdk-py: sha256:+hex(SHA256(JCS(payload)))", lambda r, p: p, _prefixed_hex),
    ("swarms/bindu: b64url(SHA256(JCS(receipt)))", lambda r, p: r, _b64url),
    ("protect-mcp: hex(SHA256(JCS(payload)))", lambda r, p: p, _hex),
    ("legacy suite: hex(SHA256(JCS(receipt minus signature)))",
     lambda r, p: {k: v for k, v in r.items() if k not in ("signature", "public_key")},
     _hex),
]


def link_of(receipt):
    """Return (field_name, value) for whichever chain field is present.

    Section 2.2 places previousReceiptHash inside the payload object, not on
    the enclosing receipt, so look there first for envelope receipts and fall
    back to the top level for flat ones.
    """
    payload = receipt.get("payload")
    if isinstance(payload, dict):
        for name in FIELD_NAMES:
            if name in payload:
                return name, payload[name]
    for name in FIELD_NAMES:
        if name in receipt:
            return name, receipt[name]
    return None, None


def payload_of(receipt):
    """The payload member for envelope receipts; the receipt minus signature for flat."""
    if isinstance(receipt.get("payload"), dict):
        return receipt["payload"]
    return {k: v for k, v in receipt.items() if k != "signature"}


def load(d: Path):
    receipts = []
    for f in sorted(d.glob("*.json")):
        try:
            receipts.append((f.name, json.loads(f.read_text())))
        except json.JSONDecodeError as e:
            print(f"  {f.name}: not valid JSON ({e})")
            sys.exit(1)
    return receipts


def seq_of(receipt):
    if "sequence" in receipt:
        return receipt["sequence"]
    p = receipt.get("payload")
    if isinstance(p, dict) and "sequence" in p:
        return p["sequence"]
    return None


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    d = Path(sys.argv[1])
    if not d.is_dir():
        print(f"  not a directory: {d}")
        return 2

    receipts = load(d)
    if not receipts:
        print(f"  no receipts in {d}: nothing to check, which is not the same as passing")
        return 1

    receipts.sort(key=lambda nr: (seq_of(nr[1]) if seq_of(nr[1]) is not None else 0, nr[0]))
    errors = []

    # Sequence must be dense and 1-based when present at all.
    if any(seq_of(r) is not None for _, r in receipts):
        for i, (name, r) in enumerate(receipts):
            got = seq_of(r)
            if got != i + 1:
                errors.append(f"{name}: sequence {got!r}, expected {i + 1}")

    # Genesis: the draft requires the member to be absent, not null or empty.
    gname, gval = link_of(receipts[0][1])
    if gname is not None and gval not in (None, ""):
        errors.append(
            f"{receipts[0][0]}: genesis carries {gname}={gval!r}; a first receipt has no predecessor")
    elif gname is not None:
        errors.append(
            f"{receipts[0][0]}: genesis carries {gname}={gval!r}; the draft requires the "
            f"member be omitted entirely, since null and \"\" change the JCS bytes and "
            f"therefore the signature")

    # Linkage: every non-genesis link must reproduce under the draft's rule.
    matched_convention = None
    for i in range(1, len(receipts)):
        name, r = receipts[i]
        prev = receipts[i - 1][1]
        fname, actual = link_of(r)
        if fname is None or not actual:
            errors.append(f"{name}: no chain link field ({'/'.join(FIELD_NAMES)})")
            continue
        if fname != "previousReceiptHash":
            errors.append(f"{name}: chain field is {fname!r}; the draft names it previousReceiptHash")

        hits = []
        for label, select, encode in CONVENTIONS:
            if encode(hashlib.sha256(jcs(select(prev, payload_of(prev)))).digest()) == actual:
                hits.append(label)
        if not hits:
            errors.append(
                f"{name}: {fname}={actual[:24]}... does not reproduce under any known "
                f"convention; the link is unrelated to the preceding receipt")
        elif not hits[0].startswith("draft:"):
            matched_convention = hits[0]
            errors.append(f"{name}: link reproduces under '{hits[0]}', not the draft rule")

    if matched_convention:
        print(f"  producer convention detected: {matched_convention}")
        print(f"  draft requires:               {CONVENTIONS[0][0]}")

    for e in errors:
        print(f"  {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
