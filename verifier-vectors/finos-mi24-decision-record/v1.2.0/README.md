# FINOS MI-24 decision records: A-DoA v1.2.0

This separate suite adapts the [historical 31 v1.1.0 cases](../README.md) and adds 19 cases for the published
A-DoA Decision Record Schema v1.2.0: **50 cases, 10 accepted, 37 rejected, 3 unsettled**. ScopeBlind authored this
follow-up with Codex. It has not been reviewed or endorsed by FINOS or the schema author. Swosti Panda's
[endorsement](https://github.com/finos/ai-governance-framework/pull/412#issuecomment-6553545848) applies to the original
31 cases only. The historical schema, receipt bytes and expected verdicts remain reproducible in the parent directory.

The [schema](schema/adoa-decision-record.schema.json) is vendored unchanged, under CC BY 4.0; see
[attribution](schema/ATTRIBUTION.md). Its exact-byte SHA-256 is
`5713e4286dc8b99d49c012db28c6534853a43d16c33bdf08521050a2f0e3821e`, verified against the author's announcement before
use. `index.json` pins the schema and MI-24 text at FINOS PR #412 commit `e668312fe060da311d27373a4ff5e3e04a43b4b7`.
The separate release rule follows [Checkable Decision Records at that exact revision](https://github.com/finos/ai-governance-framework/blob/e668312fe060da311d27373a4ff5e3e04a43b4b7/docs/_mitigations/mi-24_human-in-the-loop-action-approval-gate.md#6-recording-the-approval-evidence),
which calls a release recorded with a tripped trigger invalid. Tests use local schema bytes, so later changes at the
public schema URL do not change the results.

## Run

From the repository root:

```bash
npm install --prefix .verify --no-save --no-audit --no-fund @veritasacta/verify@0.11.1 ajv@8.20.0 ajv-formats@3.0.1
node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs --check
node verifier-vectors/finos-mi24-decision-record/v1.2.0/scripts/generate.mjs --check
VERIFY_CMD="$PWD/.verify/node_modules/.bin/verify" node verifier-vectors/finos-mi24-decision-record/run.mjs --v1.2.0
node verifier-vectors/finos-mi24-decision-record/scripts/crosscheck-ajv.mjs .verify --v1.2.0
```

Omit `--v1.2.0` from the runner and AJV cross-check to replay v1.1.0. Run the versioned generator without `--check`
to regenerate v1.2.0 only. It reads historical fixture scenarios, re-signs the adapted records with the public test
seeds, rebuilds chain links and preserves deliberately broken signatures/links. The expected outcomes are written
explicitly, not computed by the validator. Both versions run in CI on Node 20 and 22.

The v1.2.0 runner reports **68 passed, 0 failed**: 50 cases and 18 mutation checks. The independent AJV 2020-12 check
validates the schema unchanged with normal meta-schema validation enabled, asserts formats through `ajv-formats`,
checks all 50 expected schema verdicts, and agrees with the local validator on 97 payloads/variants. The v1.1.0
workaround for its fragmented `$id` remains confined to that historical version.

## What changed

| Coverage | v1.2.0 behavior |
|---|---|
| Required `decision_outcome` | All seven outcomes exercised; absent, unknown and wrong-type outcomes rejected. |
| Optional `modification_ref` | String linkage accepted with a modified action's digest; wrong type rejected. The schema alone does not require or resolve the link. |
| Strict UTC | `Z`, `+00:00` and fractional seconds accepted; nonzero/missing offsets, `-00:00` and lowercase separators rejected by the pattern. |
| Real calendar validation | `2026-02-30T22:14:05Z` rejected by asserted date-time format, although it matches the UTC pattern. Disabling format assertion is caught by the mutation sweep. |
| Schema hash | Exactly 64 lowercase hex characters required; prefixes, uppercase, short digests and the digest of JCS(schema) rather than published bytes rejected. |
| Version and `$id` | `schema_version` must equal `1.2.0`; the fragment-free `$id` compiles normally in AJV. |
| Release while tripped | `APPROVED` and `APPROVED_WITH_MODIFICATION` with status `TRIPPED` rejected by a separate MI-24 semantic rule. Trip, denial, escalation, hold and reset outcomes are not releases. |

Every case retains the receipt signature/key/chain checks, payload-schema check, exact schema naming, JCS action
digest, approver-versus-agent check, and recorded standing-grant lookup. The mutation sweep disables each check,
uses the wrong digest preimages, disables format assertion, and removes each enum; it requires the specific expected
cases to stop matching. A valid signature never substitutes for payload validation.

Three questions remain explicit: `TRIPPED` with trigger `NONE`, `CLEAR` naming `ST-01`, and a modified approval with
no `modification_ref`. v1.2.0 does not constrain these combinations, so they retain alternative readings rather than
inventing schema requirements. The runner's release rule uses status `TRIPPED`; it does not settle the contradictory
`CLEAR` case.

These are fixed synthetic decision-record checks. They do not evaluate a live gate, prove a human's authority,
resolve modification references, validate a grant's scope/expiry/revocation, recompute exposure, reconcile a reset,
or prove downstream execution. `grants.json` supplies only recorded grant identifiers; trigger evidence remains
illustrative. A trip/reset record passing these checks does not establish that the operational transition was safe.
