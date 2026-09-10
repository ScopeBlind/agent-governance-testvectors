#!/usr/bin/env python3
"""Check 3: chain order, chain linkage, and expected outcomes.

Two things were wrong with the previous check 3 (issue #13, findings 5 and 6).
It computed an expected parent digest and then discarded it, accepting any
non-empty link. And expected/chain.jsonl plus the fixtures' expected_decision
were read by no code in the repository, so a driver could ignore the policy,
emit four correctly signed receipts with arbitrary decisions, and be reported
conformant.

This check does both jobs and pins the chain rule to the published draft.

Outcomes. Each receipt's tool_name, decision and policy_id are compared to the
matching step in expected/chain.jsonl, and chain.jsonl is cross-checked against
the fixtures' expected_decision so the two sources cannot drift apart silently.

Linkage. draft-farley-acta-signed-receipts-03, section 6.7:

    previousReceiptHash = "sha256:" + lowercase-hex( SHA-256( JCS(receipt) ) )

The preimage is the ENTIRE signed receipt including its signature member, so
re-signing an identical payload yields a distinct link and a key rotation is
visible in the chain. The prefix makes the digest self-describing, matching
policy_digest and source.ref. Section 2.2 places the member inside payload and
requires the first receipt to omit it entirely: null and "" change the JCS
bytes and therefore the signature.

When a set does not satisfy the rule, this reports which convention the
producer actually used rather than failing with "mismatch". Every convention
listed below was live in at least one implementation in this repository before
the rule was settled, which is the finding that led to section 6.7.

Usage: check_chain.py <receipts_dir> <repo_root>
Exit:  0 conformant, 1 non-conformant, 2 usage/IO error.
"""
import hashlib
import json
import sys
from base64 import urlsafe_b64encode
from pathlib import Path

CANONICAL_FIELD = "previousReceiptHash"
FIELD_NAMES = (CANONICAL_FIELD, "previous_receipt_hash", "parent_receipt_hash")


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


def _minus_sig(r, p):
    return {k: v for k, v in r.items() if k not in ("signature", "public_key")}


# (label, preimage selector(receipt, payload), encoder). The first entry is the
# draft's rule; the rest are conventions in use before it was settled.
CONVENTIONS = [
    ("draft: sha256:+hex(SHA256(JCS(receipt)))", lambda r, p: r, _prefixed_hex),
    ("pre-settlement bare hex over receipt", lambda r, p: r, _hex),
    ("pre-settlement sha256:+hex over payload", lambda r, p: p, _prefixed_hex),
    ("pre-settlement b64url over receipt", lambda r, p: r, _b64url),
    ("pre-settlement bare hex over payload", lambda r, p: p, _hex),
    ("legacy suite: hex(SHA256(JCS(receipt minus signature)))", _minus_sig, _hex),
]


def field(receipt: dict, *names):
    """Receipts carry these flat or inside payload, depending on the shape."""
    for name in names:
        if name in receipt:
            return receipt[name]
    payload = receipt.get("payload")
    if isinstance(payload, dict):
        for name in names:
            if name in payload:
                return payload[name]
    return None


def link_of(receipt: dict):
    """(field_name, value) for whichever chain field is present.

    Section 2.2 places previousReceiptHash inside payload, so look there first
    for envelope receipts and fall back to the top level for flat ones.
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


def payload_of(receipt: dict):
    if isinstance(receipt.get("payload"), dict):
        return receipt["payload"]
    return {k: v for k, v in receipt.items() if k != "signature"}


def seq_of(receipt: dict):
    return field(receipt, "sequence")


def load_receipts(receipts_dir: Path):
    receipts = []
    for f in sorted(receipts_dir.glob("*.json")):
        try:
            receipts.append((f.name, json.loads(f.read_text())))
        except json.JSONDecodeError as e:
            print(f"  {f.name}: not valid JSON ({e})")
            sys.exit(1)
    receipts.sort(key=lambda nr: (seq_of(nr[1]) if seq_of(nr[1]) is not None else 0, nr[0]))
    return receipts


def load_expected_chain(repo: Path, errors: list):
    """The canonical chain the README has always said check 3 compares against."""
    path = repo / "expected" / "chain.jsonl"
    if not path.exists():
        errors.append("expected/chain.jsonl is missing; cannot verify outcomes")
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def check_fixture_agreement(repo: Path, expected_chain: list, errors: list):
    """If chain.jsonl and the fixtures disagree, neither is authoritative; say so."""
    fixtures = {}
    for f in sorted((repo / "fixtures" / "inputs").glob("*.json")):
        data = json.loads(f.read_text())
        fixtures[data.get("sequence")] = data
    for step in expected_chain:
        seq = step.get("sequence")
        fixture = fixtures.get(seq)
        if fixture is None:
            errors.append(f"chain.jsonl step {seq} has no matching fixture")
        elif fixture.get("expected_decision") != step.get("decision"):
            errors.append(
                f"fixture/chain disagreement at sequence {seq}: fixture expects "
                f"{fixture.get('expected_decision')!r}, chain.jsonl expects {step.get('decision')!r}")


def check_outcomes(name: str, receipt: dict, step: dict, errors: list):
    for key, names in (("tool_name", ("tool_name", "tool")),
                       ("decision", ("decision",))):
        want = step.get(key)
        got = field(receipt, *names)
        if want is not None and got != want:
            errors.append(f"{name}: {key} is {got!r}, expected {want!r}")

    # Policy identity. The flat shapes carry policy_id; the Acta 2.1 envelope
    # carries policy_digest, which section 6.8 of the draft makes normative.
    # Compare whichever the receipt carries against the fixture. Carrying
    # neither, or a placeholder digest, means the decision does not say which
    # policy it rested on, and that is a failure rather than a pass.
    pid = field(receipt, "policy_id")
    pdg = field(receipt, "policy_digest")
    if pid is not None:
        if step.get("policy_id") is not None and pid != step["policy_id"]:
            errors.append(f"{name}: policy_id is {pid!r}, expected {step['policy_id']!r}")
    elif pdg not in (None, "", "none"):
        if step.get("policy_digest") is None:
            errors.append(f"{name}: carries policy_digest {pdg!r} but expected/chain.jsonl has no "
                          f"policy_digest to compare it against; add one (draft section 6.8)")
        elif pdg != step["policy_digest"]:
            errors.append(f"{name}: policy_digest is {pdg!r}, expected {step['policy_digest']!r}")
    else:
        errors.append(f"{name}: carries neither policy_id nor policy_digest; "
                      f"the policy the decision rested on is not identified")


def check_genesis(name: str, receipt: dict, errors: list):
    fname, val = link_of(receipt)
    if fname is None:
        return
    if val not in (None, ""):
        errors.append(f"{name}: genesis carries {fname}={val!r}; a first receipt has no predecessor")
    else:
        errors.append(
            f"{name}: genesis carries {fname}={val!r}; the draft requires the member be "
            f"omitted entirely, since null and \"\" change the JCS bytes and therefore the signature")


def check_linkage(name: str, receipt: dict, prev: dict, errors: list):
    """Return the non-draft convention label if the link only reproduces under one."""
    fname, actual = link_of(receipt)
    if fname is None or not actual:
        errors.append(f"{name}: no chain link field ({'/'.join(FIELD_NAMES)})")
        return None
    if fname != CANONICAL_FIELD:
        errors.append(f"{name}: chain field is {fname!r}; the draft names it {CANONICAL_FIELD}")
    hits = [label for label, select, encode in CONVENTIONS
            if encode(hashlib.sha256(jcs(select(prev, payload_of(prev)))).digest()) == actual]
    if not hits:
        errors.append(f"{name}: {fname}={str(actual)[:24]}... does not reproduce under any known "
                      f"convention; the link is unrelated to the preceding receipt")
        return None
    if not hits[0].startswith("draft:"):
        errors.append(f"{name}: link reproduces under '{hits[0]}', not the draft rule")
        return hits[0]
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_chain.py <receipts_dir> <repo_root>", file=sys.stderr)
        return 2
    receipts_dir, repo = Path(sys.argv[1]), Path(sys.argv[2])
    if not receipts_dir.is_dir():
        print(f"  not a directory: {receipts_dir}")
        return 2

    errors: list = []
    receipts = load_receipts(receipts_dir)
    if not receipts:
        print(f"  no receipts in {receipts_dir}: nothing to check, which is not the same as passing")
        return 1

    expected_chain = load_expected_chain(repo, errors)
    check_fixture_agreement(repo, expected_chain, errors)
    if expected_chain and len(receipts) != len(expected_chain):
        errors.append(f"expected {len(expected_chain)} receipts, got {len(receipts)}")

    # Sequence must be dense and 1-based when the receipts carry it at all.
    if any(seq_of(r) is not None for _, r in receipts):
        for i, (name, r) in enumerate(receipts):
            if seq_of(r) != i + 1:
                errors.append(f"{name}: sequence {seq_of(r)!r}, expected {i + 1}")

    detected = None
    for i, (name, r) in enumerate(receipts):
        if i < len(expected_chain):
            check_outcomes(name, r, expected_chain[i], errors)
        if i == 0:
            check_genesis(name, r, errors)
        else:
            detected = check_linkage(name, r, receipts[i - 1][1], errors) or detected

    if detected:
        print(f"  producer convention detected: {detected}")
        print(f"  draft requires:               {CONVENTIONS[0][0]}")
    for e in errors:
        print(f"  {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
