#!/usr/bin/env python3
"""Print the verification key a receipt carries. Mutation test only.

Used by conformance/check_embedded_key.sh under
SIMULATE_EMBEDDED_KEY_RESOLUTION=1, where the point is to hand the verifier
the key the receipt supplies and confirm it then accepts. That is the
behaviour section 9.5 forbids, reproduced on purpose so the gate can be shown
to fire rather than merely asserted to.

The key is read out of the file rather than hardcoded. A constant would keep
the mutation test passing even if the vectors stopped carrying keys, which is
the failure mode this whole directory is about.

Exits 1 and prints nothing when no key is found, so the caller sees an error
instead of an empty string it might pass along as a plausible wrong answer.
"""
import json
import sys

# Ordered by how the two accepted shapes carry a key. First present wins.
PATHS = [
    ("payload", "public_key"),   # acta envelope
    ("public_key",),             # decision_receipt, top level
]


def dig(obj, path):
    for part in path:
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj if isinstance(obj, str) else None


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: extract_key.py <receipt.json>\n")
        return 2
    receipt = json.load(open(sys.argv[1]))
    found = [(p, dig(receipt, p)) for p in PATHS]
    found = [(p, k) for p, k in found if k]
    if not found:
        sys.stderr.write(
            "%s carries no key at any known path, so it cannot be a vector "
            "for a rule about embedded keys\n" % sys.argv[1])
        return 1
    # Two different keys in one receipt would make "the embedded key"
    # ambiguous, and picking one silently is how a test starts measuring
    # something other than what it claims.
    values = {k for _, k in found}
    if len(values) > 1:
        sys.stderr.write(
            "%s carries %d different keys (%s); refusing to guess which one "
            "the signature is meant to verify under\n"
            % (sys.argv[1], len(values), ", ".join(".".join(p) for p, _ in found)))
        return 1
    sys.stdout.write(found[0][1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
