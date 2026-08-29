#!/usr/bin/env python3
"""Chain order, parent-hash linkage, and expected outcomes.

Split out of verify.sh so it can be read and tested on its own.

What changed and why: check 3 previously computed the expected parent digest
and then discarded it, accepting any non-empty parent_receipt_hash. Meanwhile
expected/chain.jsonl and the fixtures' expected_decision were read by no code
in the repository at all. An implementation could ignore the Cedar policy,
emit four correctly signed receipts with arbitrary decisions, and be reported
conformant. See issue #13.
"""

import hashlib
import json
import sys
from pathlib import Path


def load_receipts(receipts_dir: Path):
    receipts = [json.loads(f.read_text()) for f in sorted(receipts_dir.glob("*.json"))]
    receipts.sort(key=lambda r: r.get("sequence", 0))
    return receipts


def load_expected_chain(repo: Path, errors: list):
    """The canonical chain the README has always said check 3 compares against."""
    path = repo / "expected" / "chain.jsonl"
    if not path.exists():
        errors.append("expected/chain.jsonl is missing; cannot verify outcomes")
        return []
    steps = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            steps.append(json.loads(line))
    return steps


def check_fixture_agreement(repo: Path, expected_chain: list, errors: list):
    """Guard the two fixture sources against drifting apart.

    If chain.jsonl and the fixtures disagree about an expected decision, neither
    can be authoritative, and the suite should say so rather than silently pick
    one and report a pass.
    """
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
                f"{fixture.get('expected_decision')!r}, chain.jsonl expects "
                f"{step.get('decision')!r}"
            )


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


def canonical_form(receipt: dict) -> str:
    return json.dumps(
        {k: v for k, v in receipt.items() if k not in ("signature", "public_key")},
        sort_keys=True,
        separators=(",", ":"),
    )


def check_outcomes(receipt: dict, step: dict, index: int, errors: list):
    for key, names in (
        ("tool_name", ("tool_name", "tool")),
        ("decision", ("decision",)),
        ("policy_id", ("policy_id",)),
    ):
        want = step.get(key)
        got = field(receipt, *names)
        if want is not None and got != want:
            errors.append(f"receipt {index}: {key} is {got!r}, expected {want!r}")


def check_linkage(receipt: dict, prev_canonical, index: int, errors: list):
    parent = receipt.get("parent_receipt_hash")
    if index == 0:
        if parent not in (None, ""):
            errors.append(
                f"receipt 0: genesis should have null/empty parent_receipt_hash, got {parent!r}"
            )
        return
    if not parent:
        errors.append(f"receipt {index}: missing parent_receipt_hash")
        return
    if prev_canonical is None:
        return
    # Implementations may truncate the parent hash, so a prefix match is
    # accepted. That is what the original comment intended; the computed value
    # was simply never compared against anything.
    expected = hashlib.sha256(prev_canonical.encode()).hexdigest()
    supplied = str(parent).lower()
    if supplied.startswith("sha256:"):
        supplied = supplied[len("sha256:"):]
    if not expected.startswith(supplied):
        errors.append(
            f"receipt {index}: parent_receipt_hash {parent!r} does not match the "
            f"predecessor digest {expected[:16]}..."
        )


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_chain.py <receipts_dir> <repo_root>", file=sys.stderr)
        return 2

    receipts_dir = Path(sys.argv[1])
    repo = Path(sys.argv[2])

    errors: list = []
    receipts = load_receipts(receipts_dir)
    expected_chain = load_expected_chain(repo, errors)
    check_fixture_agreement(repo, expected_chain, errors)

    if expected_chain and len(receipts) != len(expected_chain):
        errors.append(f"expected {len(expected_chain)} receipts, got {len(receipts)}")

    prev_canonical = None
    for index, receipt in enumerate(receipts):
        expected_seq = index + 1
        if receipt.get("sequence") != expected_seq:
            errors.append(
                f"receipt {index}: sequence {receipt.get('sequence')} != expected {expected_seq}"
            )
        if index < len(expected_chain):
            check_outcomes(receipt, expected_chain[index], index, errors)
        check_linkage(receipt, prev_canonical, index, errors)
        prev_canonical = canonical_form(receipt)

    if errors:
        for error in errors:
            print(f"  {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
