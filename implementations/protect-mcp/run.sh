#!/usr/bin/env bash
# Reference driver: protect-mcp (TypeScript / npm).
# Reads fixtures from ../../fixtures/, writes receipts to ../../receipts/protect-mcp/.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/fixtures"
OUT="$REPO_ROOT/receipts/protect-mcp"
mkdir -p "$OUT"

command -v npx >/dev/null 2>&1 || { echo "skip: npx not found"; exit 77; }

POLICY="$FIXTURES/policy/autoresearch-safe.cedar"

# A deterministic key file derived from the fixture seed. In a real
# production implementation the seed → private-key derivation would use
# the standard Ed25519 RFC 8032 procedure; for the reference driver we
# hand-compute this once and store it.
#
# Note: this directory contains a seed file; protect-mcp itself generates
# keys on first run if none exist. For a conformance run we want the seed
# to be shared, so we pre-populate a key file.
KEY="$OUT/.key"
if [ ! -f "$KEY" ]; then
    # Seed -> Ed25519 private key bytes. protect-mcp accepts --key as a
    # hex-encoded 32-byte seed. Use the fixture seed.
    printf '%s\n' "0000000000000000000000000000000000000000000000000000000000000001" > "$KEY"
fi

# Evaluate each input then sign
for input_file in "$FIXTURES/inputs"/*.json; do
    name="$(basename "$input_file" .json)"
    tool_name="$(python3 -c "import json; print(json.load(open('$input_file'))['tool_name'])")"
    tool_input="$(python3 -c "import json; print(json.dumps(json.load(open('$input_file'))['tool_input']))")"

    # Evaluate (we ignore exit code here; downstream sign records the decision)
    DECISION_RC=0
    npx --yes protect-mcp@latest evaluate \
        --policy "$POLICY" \
        --tool "$tool_name" \
        --input "$tool_input" \
        --fail-on-missing-policy false >/dev/null 2>&1 || DECISION_RC=$?

    # Sign produces the receipt regardless of the evaluate outcome.
    # protect-mcp writes to a filename based on timestamp; we rename to
    # sequence order for deterministic output.
    TMPDIR="$OUT/.tmp-$name"
    mkdir -p "$TMPDIR"
    npx --yes protect-mcp@latest sign \
        --tool "$tool_name" \
        --input "$tool_input" \
        --output "{}" \
        --receipts "$TMPDIR/" \
        --key "$KEY" >/dev/null 2>&1 || true

    produced="$(ls "$TMPDIR"/*.json 2>/dev/null | head -1)"
    if [ -n "$produced" ] && [ -f "$produced" ]; then
        mv "$produced" "$OUT/$name.json"
    fi
    rm -rf "$TMPDIR"
done

echo "protect-mcp: $(ls "$OUT"/*.json 2>/dev/null | wc -l) receipts in $OUT"
