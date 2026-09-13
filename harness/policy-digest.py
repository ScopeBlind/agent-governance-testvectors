#!/usr/bin/env python3
"""Recompute the policy_digest expected/chain.jsonl carries, per draft-farley-acta-signed-receipts-03 section 6.8
(acta-policy-digest-v1). Usage: harness/policy-digest.py [fixtures/policy/autoresearch-safe.cedar ...]"""
import hashlib, json, os, sys
files = sys.argv[1:] or ["fixtures/policy/autoresearch-safe.cedar"]
entries = sorted(({"name": os.path.basename(f), "sha256": hashlib.sha256(open(f, "rb").read()).hexdigest()} for f in files), key=lambda e: e["name"])
manifest = {"construction": "acta-policy-digest-v1", "engine": "cedar", "files": entries}
jcs = json.dumps(manifest, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
print("sha256:" + hashlib.sha256(jcs).hexdigest())
