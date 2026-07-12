# Nobulex conformance driver

Python implementation producing v1 flat receipts with Ed25519 signatures
over JCS-canonical bytes.

## What Nobulex is

Credit scores for AI agents. An agent commits to its rulebook before it
acts, every action leaves a signed receipt, and the verified track record
becomes portable trust. The `action_ref` formula is normative implementation
guidance in OWASP Agentic Skills Top 10 (AST09).

- PyPI: `pip install nobulex`
- npm: `npm install @nobulex/core`
- GitHub: https://github.com/arian-gogani/nobulex

## Running

```bash
# From the repo root
NOBULEX_PYTHON=/path/to/nobulex/packages/python \
  python implementations/nobulex/driver.py
```

Or with nobulex installed via pip:

```bash
pip install nobulex
python implementations/nobulex/driver.py
```

## What it produces

4 v1 flat receipts in `output/`, one per test fixture:

| Seq | Tool  | Decision | Signature | Chain |
|-----|-------|----------|-----------|-------|
| 1   | Read  | allow    | verified  | genesis |
| 2   | Bash  | allow    | verified  | linked |
| 3   | Bash  | deny     | verified  | linked |
| 4   | Write | allow    | verified  | linked |

All signatures are Ed25519 over JCS-canonical payload (signature field
excluded from signed bytes). Chain linked via `parent_receipt_hash` =
SHA-256 of the previous receipt's JCS-canonical form.

## Conformance checks

- Schema: v1 flat shape per `expected/receipt-schema.json`
- Signatures: Ed25519, verified against deterministic test keypair
- Chain: `parent_receipt_hash` forms valid ordered chain from genesis
