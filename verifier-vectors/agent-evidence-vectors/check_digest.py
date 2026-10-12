#!/usr/bin/env python3
"""Check the installed receipt-signature corpus against the signed digest list of its release.

Usage: check_digest.py CORPUS-DIGESTS.txt

CORPUS-DIGESTS.txt is the release asset whose signature the workflow has already checked with cosign. This reads the
line for vectors-receipt-signature and compares it to the corpusDigest and vector count in the installed MANIFEST.json,
so the run below is known to replay the corpus the release signed and nothing else.
"""

import json
import os
import sys

import agent_evidence_vectors

CORPUS = "vectors-receipt-signature"


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    signed = None
    with open(sys.argv[1], encoding="utf-8") as source:
        for line in source:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == f"{CORPUS}/MANIFEST.json":
                signed = fields
    if signed is None:
        print(f"{CORPUS} has no line in {sys.argv[1]}", file=sys.stderr)
        return 1
    root = os.path.join(os.path.dirname(agent_evidence_vectors.__file__), "corpora", CORPUS)
    with open(os.path.join(root, "MANIFEST.json"), encoding="utf-8") as source:
        manifest = json.load(source)
    declared = manifest.get("corpusDigest")
    count = f"vectors={len(manifest.get('vectors', []))}"
    if declared != signed[0] or count != signed[3]:
        print(f"installed {CORPUS}: {declared} {count}; signed: {signed[0]} {signed[3]}", file=sys.stderr)
        return 1
    print(f"{CORPUS}: {declared} {count} matches the signed digest list")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
