#!/usr/bin/env python3
"""
GDI (Governed Decision Intelligence) driver for agent-governance-testvectors.

Produces v2 structured-envelope receipts with a GDR payload embedded in
`payload.gdr`. The GDR captures pre-decision reasoning state: confidence
score, gate classification, evidence completeness, and accountability chain.

Wire format: v2 envelope conforming to draft-farley-acta-signed-receipts.
Verified by @veritasacta/verify.

Apache-2.0. https://github.com/mj3b/governed-decision-intelligence
"""

from __future__ import annotations
import base64, hashlib, json, sys, time
from pathlib import Path

import cedarpy
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Conformance keypair -- testing only
SEED = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
_PRIV = Ed25519PrivateKey.from_private_bytes(SEED)
_PUB  = _PRIV.public_key().public_bytes_raw()
PUBKEY_HEX = _PUB.hex()
_KID = base64.urlsafe_b64encode(hashlib.sha256(_PUB).digest()[:16]).rstrip(b"=").decode()


def evaluate_cedar(tool_name: str, context: dict, policy: str) -> str:
    """Evaluate the actual fixture policy; diagnostic errors are not denials."""
    result = cedarpy.is_authorized({
        "principal": 'User::"agent"',
        # Cedar string escapes are not JSON's \uXXXX, so keep non-ASCII as is.
        "action": 'Action::' + json.dumps(tool_name, ensure_ascii=False),
        "resource": 'Resource::"tool"',
        "context": context,
    }, policy, [])
    errors = list(getattr(result.diagnostics, "errors", []) or [])
    if errors:
        raise ValueError(f"Cedar evaluation failed for {tool_name}: {errors}")
    return "allow" if str(result.decision).endswith("Allow") else "deny"


GATE_MAP = {
    ("allow","Read"):      ("routine",              0.92),
    ("allow","Glob"):      ("routine",              0.90),
    ("allow","Grep"):      ("routine",              0.90),
    ("allow","WebSearch"): ("routine",              0.88),
    ("allow","Bash"):      ("elevated_review",      0.78),
    ("allow","Write"):     ("elevated_review",      0.75),
    ("allow","Edit"):      ("elevated_review",      0.75),
    ("deny", "Bash"):      ("blocked",              0.15),
    ("deny", "Write"):     ("mandatory_escalation", 0.22),
    ("deny", "Edit"):      ("mandatory_escalation", 0.22),
}

def build_gdr(tool_name, tool_input, context, decision, policy_id,
              session_id, sequence, timestamp):
    gate_class, confidence = GATE_MAP.get((decision, tool_name), ("deferred", 0.50))
    evidence_sources = []
    if tool_input:
        evidence_sources.append({"completeness":"complete",
            "fields_present":sorted(tool_input.keys()), "source":"tool_input"})
    if context:
        evidence_sources.append({"completeness":"complete",
            "fields_present":sorted(context.keys()), "source":"context"})
    # The decision comes from the Cedar policy and the score from GATE_MAP, so
    # the text makes no threshold claim: no threshold is applied.
    reasoning = (
        f"{tool_name} evaluated against {policy_id}. Gate: {gate_class}. "
        + (f"Confidence {confidence:.2f}. Action approved."
           if decision == "allow"
           else f"Confidence {confidence:.2f}. Forbid matched or no permit applied. Action blocked.")
    )
    return {
        "accountability_chain": [
            {"identity": f"session:{session_id}", "responsibility": "policy_evaluation", "role": "agent_runtime"},
            {"identity": "human:operator",        "responsibility": "threshold_approval",  "role": "governance_owner"},
        ],
        "confidence_score":         confidence,
        "decision":                 decision,
        "evidence_sources":         evidence_sources,
        "gate_classification":      gate_class,
        "gdr_timestamp":            timestamp,
        "gdr_version":              "2.0",
        "policy_id":                policy_id,
        "reasoning_reconstruction": reasoning,
        "sequence":                 sequence,
        "session_id":               session_id,
        "tool_input":               tool_input,
        "tool_name":                tool_name,
    }

def jcs(obj) -> bytes:
    # Python json.dumps is not JCS for all numbers or UTF-16 property ordering.
    return rfc8785.dumps(obj)

def sha256p(data) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def policy_digest(policy_name: str, policy_bytes: bytes) -> str:
    """Bind the exact evaluated bytes using acta-policy-digest-v1."""
    return sha256p(jcs({
        "construction": "acta-policy-digest-v1",
        "engine": "cedar",
        "files": [{"name": policy_name,
                   "sha256": hashlib.sha256(policy_bytes).hexdigest()}],
    }))


def build_receipt(fixture: dict, sequence: int, prev_canonical: bytes | None,
                  policy: str, digest: str):
    tool_name  = fixture["tool_name"]
    tool_input = fixture.get("tool_input", {})
    context    = fixture.get("context", {})
    session_id = fixture.get("session_id", "testvectors-session-001")
    policy_id  = "autoresearch-safe"
    decision   = evaluate_cedar(tool_name, context, policy)
    timestamp  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    gdr = build_gdr(tool_name, tool_input, context, decision, policy_id,
                    session_id, sequence, timestamp)

    # Assemble complete receipt (all fields) BEFORE signing
    # The verifier hashes the full object minus the signature field
    receipt = {
        "algorithm":           "ed25519",
        "issued_at":           timestamp,
        "issuer":              "gdi:governed-decision-intelligence",
        "kid":                 _KID,
        "payload": {
            "action":        {"kind": tool_name, "target": session_id},
            "decision":      decision,
            "gdr":           gdr,
            "params_hash":   sha256p(jcs(tool_input)) if tool_input else None,
            "policy_digest": digest,
            "policy_id":     policy_id,
            "result_hash":   sha256p(jcs(gdr)),
            "reason_code":   "policy_match" if decision == "allow" else "policy_deny",
            "sequence":      sequence,
            "session_id":    session_id,
            "tier":          "evidenced",
            "timestamp":     timestamp,
            "tool":          tool_name,
            "type":          "scopeblind.receipt.v2",
        },
        "pubkey":   PUBKEY_HEX,
        "sequence": sequence,
        "type":     "decision_receipt",
        "v":        2,
    }
    # The genesis receipt has no link member, including no legacy null alias.
    if prev_canonical is not None:
        receipt["payload"]["previousReceiptHash"] = sha256p(prev_canonical)

    # Sign JCS of receipt without the signature field
    canonical_bytes = jcs(receipt)
    receipt["signature"] = _PRIV.sign(canonical_bytes).hex()

    # The next link commits to the ENTIRE signed receipt, not the signing input.
    return receipt, jcs(receipt)


def emit(repo_root: Path):
    fixtures_dir = repo_root / "fixtures" / "inputs"
    fixtures = sorted(fixtures_dir.glob("*.json"))
    if not fixtures:
        raise ValueError(f"No fixture files found in {fixtures_dir}")
    policy_path = repo_root / "fixtures" / "policy" / "autoresearch-safe.cedar"
    policy_bytes = policy_path.read_bytes()
    policy = policy_bytes.decode("utf-8")
    digest = policy_digest(policy_path.name, policy_bytes)

    out_dir = repo_root / "receipts" / "gdi"

    prev_canonical = None
    pending = []
    for count, f in enumerate(fixtures):
        fixture  = json.loads(f.read_text(encoding="utf-8"))
        sequence = fixture.get("sequence", count + 1)
        receipt, canonical = build_receipt(fixture, sequence, prev_canonical,
                                           policy, digest)
        pending.append((f.name, json.dumps(receipt, indent=2, ensure_ascii=False) + "\n"))
        prev_canonical = canonical

    # Evaluate and sign the full batch before replacing the previous output.
    # A malformed fixture or policy must not leave a truncated successful chain.
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.json"):
        stale.unlink()
    for name, content in pending:
        (out_dir / name).write_text(content, encoding="utf-8")
    print(f"gdi: {len(pending)} receipts in {out_dir}")


def main():
    try:
        emit(Path(__file__).resolve().parents[2])
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"gdi: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
