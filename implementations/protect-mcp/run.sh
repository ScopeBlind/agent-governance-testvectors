#!/usr/bin/env bash
# Reference driver: protect-mcp (TypeScript / npm).
# Reads fixtures from ../../fixtures/, writes receipts to ../../receipts/protect-mcp/.
#
# The previous version of this driver produced zero receipts and reported
# success. It passed a raw hex seed to --key (protect-mcp expects a JSON key
# file with privateKey/publicKey), passed --input/--output flags that the sign
# verb does not read, and then collected *.json from a directory into which
# protect-mcp writes receipts.jsonl. Each of those alone yields no output, and
# the `|| true` hid all three. This version pipes the fixture on stdin the way
# a PostToolUse hook does, writes a real key file, reads the JSONL, and fails
# loudly when nothing is signed.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/fixtures"
OUT="$REPO_ROOT/receipts/protect-mcp"
rm -rf "$OUT" && mkdir -p "$OUT"

command -v npx >/dev/null 2>&1 || { echo "skip: npx not found"; exit 77; }
command -v node >/dev/null 2>&1 || { echo "skip: node not found"; exit 77; }

PMCP="${PROTECT_MCP_CMD:-npx --yes protect-mcp@latest}"
POLICY="$FIXTURES/policy/autoresearch-safe.cedar"
SEED="0000000000000000000000000000000000000000000000000000000000000001"

# protect-mcp reads a JSON key file, not a bare seed. Derive the keypair from
# the shared fixture seed so every implementation signs under the same key.
KEY="$OUT/.key.json"
node -e '
const c = require("node:crypto");
const seed = process.argv[1];
const priv = c.createPrivateKey({
  key: Buffer.from("302e020100300506032b657004220420" + seed, "hex"),
  format: "der", type: "pkcs8",
});
const pub = Buffer.from(c.createPublicKey(priv).export({format:"der",type:"spki"}).slice(-32)).toString("hex");
require("node:fs").writeFileSync(process.argv[2], JSON.stringify({
  privateKey: seed, publicKey: pub, kid: "conformance",
}, null, 2));
' "$SEED" "$KEY"

WORK="$OUT/.work"
rm -rf "$WORK" && mkdir -p "$WORK"

signed_count=0
for input_file in "$FIXTURES/inputs"/*.json; do
    name="$(basename "$input_file" .json)"
    tool_name="$(node -p "JSON.parse(require('fs').readFileSync('$input_file','utf8')).tool_name")"
    tool_input="$(node -p "JSON.stringify(JSON.parse(require('fs').readFileSync('$input_file','utf8')).tool_input)")"

    # Evaluate for the decision; sign records a receipt either way.
    $PMCP evaluate --policy "$POLICY" --tool "$tool_name" --input "$tool_input" \
        --fail-on-missing-policy false >/dev/null 2>&1 || true

    # One shared log for the whole run: receipts chain to their predecessor, so
    # giving each fixture a fresh directory would produce four unlinked
    # genesis receipts instead of a chain.
    result="$(node -e '
      const fs = require("node:fs");
      const f = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(JSON.stringify({
        tool_name: f.tool_name, tool_input: f.tool_input, tool_response: {},
      }));
    ' "$input_file" | $PMCP sign --receipts "$WORK" --key "$KEY" 2>/dev/null)"

    line="$(tail -n 1 "$WORK/receipts.jsonl" 2>/dev/null || true)"
    if [ -n "$line" ] && node -e '
        const r = JSON.parse(process.argv[1]);
        process.exit(r.signature && r.signature.sig ? 0 : 1);
      ' "$line" 2>/dev/null; then
        printf '%s\n' "$line" > "$OUT/$name.json"
        signed_count=$((signed_count + 1))
    else
        echo "protect-mcp: $name produced no signed receipt: ${result:-<no output>}" >&2
    fi
done
rm -rf "$WORK"

rm -f "$KEY"

total="$(ls "$FIXTURES/inputs"/*.json 2>/dev/null | wc -l | tr -d ' ')"
echo "protect-mcp: $signed_count/$total signed receipts in $OUT"

# Producing nothing is a failure, not a pass. The previous driver exited 0 here.
if [ "$signed_count" -eq 0 ]; then
    echo "protect-mcp: no receipts were signed; the sign verb needs a version that" >&2
    echo "  resolves a signer (published 0.11.1 exits 0 without signing)." >&2
    exit 1
fi
exit 0
