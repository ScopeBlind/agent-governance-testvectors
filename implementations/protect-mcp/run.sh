#!/usr/bin/env bash
# Reference driver: protect-mcp (TypeScript / npm).
# Reads fixtures from ../../fixtures/, writes receipts to ../../receipts/protect-mcp/.
#
# Honest status. protect-mcp's `sign` verb signs a post-execution receipt for
# a tool call. It does not evaluate a policy: it ignores --cedar and --policy,
# and it ignores a decision supplied on stdin or by flag. `evaluate` returns a
# verdict but cannot sign, and on this fixture policy it denies the Read call
# the policy permits, so its verdict could not be trusted either. This driver
# therefore produces four correctly signed, correctly chained receipts, every
# one of which says "allow", including the destructive-Bash fixture the policy
# forbids, and none of which identifies the policy it rested on. Check 3 fails
# the reference implementation on exactly that, which is issue #13 finding 6
# landing where it should. The fix is a policy-signing path in protect-mcp,
# not a driver that fabricates the decision to make the suite go green.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/fixtures"
OUT="$REPO_ROOT/receipts/protect-mcp"
rm -rf "$OUT" && mkdir -p "$OUT"

command -v npx >/dev/null 2>&1 || { echo "skip: npx not found"; exit 77; }
command -v node >/dev/null 2>&1 || { echo "skip: node not found"; exit 77; }

PMCP="${PROTECT_MCP_CMD:-npx --yes protect-mcp@latest}"

# Deterministic test keypair: fixtures/keys/README.md documents the seed.
# protect-mcp accepts --key as a JSON file carrying the 32-byte seed.
SEED="0000000000000000000000000000000000000000000000000000000000000001"
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
if [ "$signed_count" -eq 0 ]; then
    echo "protect-mcp: no receipts were signed; the sign verb needs a version that" >&2
    echo "  resolves a signer (0.12.0 does; 0.11.1 exits 0 without signing)." >&2
    exit 1
fi
exit 0
