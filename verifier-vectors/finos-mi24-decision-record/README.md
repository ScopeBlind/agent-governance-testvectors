# FINOS MI-24 decision records as Acta receipts: vectors for the A-DoA schema v1.1.0

**Status:** test vectors for the
[A-DoA Decision Record Schema v1.1.0](https://swostipanda.github.io/schemas/adoa-decision-record.schema.json) by
Swosti Panda: the schema that MI-24 in [finos/ai-governance-framework](https://github.com/finos/ai-governance-framework)
cites ([#412](https://github.com/finos/ai-governance-framework/pull/412)), whose required fields are the members MI-24
lists. The records here are carried as Veritas Acta receipts. **Neither FINOS nor the schema's author has reviewed or
endorsed these vectors.**

**Provenance:** written by ScopeBlind, which maintains draft-farley-acta-signed-receipts and `@veritasacta/verify`,
with AI coding agents (Claude). It is the receipt format author's own work, not an independent evaluation.

## Why it exists

MI-24 (Human-in-the-Loop Action Approval Gate), as #412 has it at head `490d0fd7`, asks that each decision record be
serialized against a versioned JSON Schema and name it by version and by the SHA-256 of its bytes. Its Additional
Resources cite the A-DoA framework, whose author publishes that schema. Its Conformance bullet says a record may travel
as the signed payload of a draft-farley-acta-signed-receipts decision receipt, which "allows mi-24 approval records to be
checked by the same mi-21 receipt-signature conformance run". That run checks a receipt's signature, key window and
chain link. It reads none of the record's fields.

These vectors check both: the receipt, with the published verifier, and the record, against the published schema and
against the rules MI-24's text adds beyond it. `index.json` pins the MI-24 text (the file at #412's head, with its
SHA-256) and the schema (its bytes, with their SHA-256).

## Run

From the repository root:

```bash
# The pinned verifier, and ajv for the cross-check, in a temporary prefix (.verify/ is gitignored)
npm install --prefix .verify --no-save --no-audit --no-fund @veritasacta/verify@0.11.1 ajv@8.20.0 ajv-formats@3.0.1
VERIFY_CMD="$PWD/.verify/node_modules/.bin/verify" node verifier-vectors/finos-mi24-decision-record/run.mjs
node verifier-vectors/finos-mi24-decision-record/scripts/crosscheck-ajv.mjs .verify

# Or through npx, with nothing installed
node verifier-vectors/finos-mi24-decision-record/run.mjs

# Rewrite every generated file, or check that each is current
node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs
node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs --check
```

`run.mjs` exits 0 when every case matched and every mutation was caught, 1 otherwise, and 77 when the pinned verifier
cannot run here. On `@veritasacta/verify` 0.11.1 (published with npm provenance) it reports `47 passed, 0 failed`: 31
cases, then 16 mutations. CI runs the generator check, the runner and the cross-check on Node 20 and 22.

## What is here

| Path | What it holds |
|---|---|
| `schema/adoa-decision-record.schema.json` | The A-DoA Decision Record Schema v1.1.0, unchanged. |
| `schema/ATTRIBUTION.md` | Its author, source, DOI, licence (CC BY 4.0) and SHA-256. |
| `records/` | 30 receipts and 2 logs of two receipts each, signed with seeded test keys. |
| `actions/` | The resolved actions that `resolved_action_digest` is checked against. |
| `issuer-jwks.json` | The pinned gate key: the only key the verifier is given. |
| `grants.json` | The recorded standing approvals that a `grant_id` resolves against. |
| `index.json` | Every case: its parent, its one change, the check kinds that decide it, and the expected result of each check. |
| `lib.mjs` | The schema check and the other rules, with no dependencies. |
| `run.mjs` | The runner. |
| `scripts/generate.mjs` | Writes every file but the schema, and refuses to run if a byte of the schema differs. `--check` fails on a stale file. |
| `scripts/crosscheck-ajv.mjs` | Runs the payloads through ajv, with and without ajv-formats, beside `lib.mjs`. |

## The schema

`schema/adoa-decision-record.schema.json` is the published file, byte for byte: 4,573 bytes, SHA-256
`e5a4c6108e9df21863ec69ea80a3ee588ede3e8a27a74924305264bb7c5a549e`, `$id`
`https://swostipanda.github.io/schemas/adoa-decision-record.schema.json#v1.1.0`. It is by Swosti Panda, is licensed CC BY
4.0, and accompanies the A-DoA framework ([10.5281/zenodo.23275115](https://doi.org/10.5281/zenodo.23275115)).
`schema/ATTRIBUTION.md` has the full attribution. `generate.mjs` refuses to run if a byte differs, and `.gitattributes`
keeps git from rewriting its line endings.

Records name it with `schema_version` `1.1.0` and `schema_sha256`. The schema states no encoding for `schema_sha256`,
so these vectors use the lowercase hex of the file's SHA-256, 64 characters with no prefix, and hold every record to it.

## The receipts

Each receipt has the envelope shape of draft-farley-acta-signed-receipts and is signed with Ed25519 over JCS(payload).
The payload is one A-DoA record plus the receipt's own members (Section 2.2): `type`, `issuer_id`, `issued_at`, and
`previousReceiptHash` when the record follows another (Section 6.7). `type` is
`x-agent-governance-testvectors:mi24-decision-record`, a placeholder in this repository's namespace. The schema does not
forbid other members, so the receipt's members do not affect it.

Three records are parents, and every other case makes one change to one of them:

- `gated-approval`: a per-action approval of a 25,000 USD payment (`T1_HUMAN_APPROVAL_REQUIRED`, `PER_ACTION_APPROVAL`),
  with the breakers `CLEAR`.
- `standing-approval-chain`, line 2: a ticket released under a recorded standing grant (`T2_BOUNDED_AUTO_EXECUTE`,
  `STANDING_BOUNDED_GRANT`), linked to the approval.
- `trip-record`: an ST-01 trip under unattended T2 execution (`UNATTENDED_T2`, status `TRIPPED`), with the rolling
  total, the ceiling and the policy version in `trigger_evidence`.

Identifiers, amounts and the members inside `trigger_evidence` are illustrative; the schema defines none of them.

## Four kinds of check

| Kind | Checks | Decided by | Passes when |
|---|---|---|---|
| (a) The Acta receipt | `signature` | `@veritasacta/verify` 0.11.1 | The signature verifies under the pinned key set, over a signing input with no signature member (Section 6.6). |
| | `key` | the verifier's report | The record names the pinned gate key (`issuer_id` is `signature.kid`), the verifier resolved it from the pinned set, and the signed `issued_at` is inside its window. |
| | `chain` | `verify --replay-chain` | In a log, each record's `previousReceiptHash` is the Section 6.7 link of the record before it. |
| (b) The A-DoA v1.1.0 schema | `schema` | `lib.mjs` | The payload validates against the vendored schema. `format` is an annotation, as draft 2020-12 has it by default. |
| (c) The schema's name and the digests | `schema_named` | `lib.mjs` | `schema_version` is `1.1.0` and `schema_sha256` is the SHA-256 of the pinned file's bytes. |
| | `action_digest` | `lib.mjs` | `resolved_action_digest` names the SHA-256 over the RFC 8785 bytes of the resolved action and arguments, as the schema's description says. Its form is the schema's pattern, so (b) decides that and this compares the value. |
| (d) From MI-24's text, beyond the schema | `approver_not_agent` | `lib.mjs` | `human_approver.principal_id` is not `agent_id` (MI-24 Checkable Decision Records). |
| | `grant_recorded` | `lib.mjs` | Where `oversight_pattern` is `STANDING_BOUNDED_GRANT` or `UNATTENDED_T2`, `grant_id` names a standing approval in `grants.json` (MI-24 Checkable Decision Records). |

The (d) checks are MI-24's, not the schema's: a record can conform to v1.1.0 and fail them. A check that does not apply
to a record is `not_run`. The verdict combines the checks as Section 5.3 of the -04 editor's copy (VeritasActa/drafts#6)
does: invalid if a check ran and failed, undecidable if none failed and one could not decide, otherwise valid. Every
date-time the schema reaches is reported beside the result as holding or not, without deciding it.

## The cases

Thirty-one: 3 accepted, 22 rejected, and 6 that neither the schema nor MI-24 settles. "The verifier" is what
`@veritasacta/verify` 0.11.1 reports for the receipt. Where it reports a valid receipt and the case expects REJECT, the
receipt is sound and the record is not: that is the gap between the mi-21 run and a check of the record.

### Accepted

| Case | What it is | The verifier |
|---|---|---|
| `gated-approval` | a parent | valid |
| `standing-approval-chain` | two records, linked | valid, one chain |
| `trip-record` | a parent | valid |

### (a) Rejected by the Acta receipt

| Case | Change from its parent | Checks that do not pass | The verifier |
|---|---|---|---|
| `signature-altered` | last hex digit of the signature | signature | invalid, `invalid_signature` |
| `field-changed-after-signing` | `blast_radius_usd` 25000 to 2500, signature kept | signature | invalid, `invalid_signature` |
| `unexpected-signer` | signed with the agent's own key, which it names | signature (undecidable), key | undecidable, exit 2, `jwks_fetch_failed` |
| `broken-chain` | line 1 rewritten and signed again after line 2 linked it | chain | invalid, `chain_break` on line 2 |

### (b) Rejected by the A-DoA v1.1.0 schema

| Case | Change from its parent | Schema rule |
|---|---|---|
| `missing-decision-id` | `decision_id` removed | `required` |
| `missing-human-approver` | `human_approver` removed | `required` |
| `trip-record-no-approver` | `human_approver` null on the trip record | `type` object: v1.1.0 requires an approver on every record, a trip included |
| `evidence-refs-not-array` | one string instead of an array | `type` array |
| `autonomy-tier-outside-enum` | `T1_ACT_AND_NOTIFY`, the v1.0 specification's name for T1 | `enum` |
| `oversight-pattern-outside-enum` | `MAKER_CHECKER`, MI-24's own name for the pattern | `enum` |
| `trigger-status-outside-enum` | status `SUSPENDED` | `enum` |
| `tripped-trigger-st-06` | `tripped_trigger` `ST-06` | `enum` |
| `triggers-evaluated-st-06` | `ST-06` among `triggers_evaluated` | `enum` |
| `trigger-state-missing-triggers-evaluated` | `triggers_evaluated` removed | `required` |
| `blast-radius-negative` | `blast_radius_usd` -25000 | `minimum` 0 |
| `action-digest-no-prefix` | the right digest without `sha256:` | `pattern` |
| `action-digest-uppercase` | the right digest in uppercase hex | `pattern` |
| `schema-version-1-0-0` | `schema_version` `1.0.0` | `const`, and (c) too |

In every one the verifier reports a valid receipt.

### (c) Rejected by the schema's name or the digests

| Case | Change from its parent | Checks that do not pass |
|---|---|---|
| `schema-sha256-mismatch` | the SHA-256 of the schema's RFC 8785 form, not its bytes | schema_named |
| `action-digest-mismatch` | none to the receipt; the action presented pays another account | action_digest |

The schema accepts any string as `schema_sha256`, so only (c) sees the first.

### (d) Rejected by MI-24's text, beyond the schema

| Case | Change from its parent | Checks that do not pass |
|---|---|---|
| `approver-is-agent` | `principal_id` set to `agent_id` | approver_not_agent |
| `grant-not-recorded` | a `grant_id` no recorded grant carries | grant_recorded |

Both records conform to the schema.

### Not settled

As in the agent-audit-record corpus of agent-evidence-vectors, these carry no expected verdict. Each lists the readings
a conforming verifier may take, and `index.json` gives the reason for each.

| Case | Kind | The question | This runner reads it as |
|---|---|---|---|
| `timestamp-not-utc` | (b) | The same instant at +11:00. A date-time may carry any offset, asserted or not; only the description says UTC. | ACCEPT |
| `timestamp-no-offset` | (b) | No offset at all. Valid while `format` is an annotation; ajv-formats refuses it when asserted. | ACCEPT |
| `schema-sha256-prefixed` | (c) | The right digest written as `sha256:` and hex. The schema states no encoding. | REJECT |
| `release-while-tripped` | (d) | A release under a standing grant while ST-01 is `TRIPPED`. MI-24 calls it a contradiction, but no field records an outcome, and `trip-record` has the same shape. | ACCEPT |
| `tripped-with-trigger-none` | (b) | Status `TRIPPED`, `tripped_trigger` `NONE`. | ACCEPT |
| `clear-naming-st-01` | (b) | Status `CLEAR`, `tripped_trigger` `ST-01`. | ACCEPT |

## Format, asserted and not

Draft 2020-12 reads `format` as an annotation unless a validator is told to assert it, so `lib.mjs` reports each
date-time beside the result without letting it decide. `scripts/crosscheck-ajv.mjs` compares it with ajv 8.20.0 on the
34 record payloads (the 30 receipts and the four lines of the two logs) and 39 variants, 73 in all:

- ajv refuses to compile the schema as published: its `$id` ends in the fragment `#v1.1.0`, and the 2020-12
  meta-schema allows none. The comparison compiles the same bytes with meta-schema validation off.
- With `format` an annotation, `lib.mjs` and ajv agree on all 73.
- With `format` asserted, `lib.mjs` (RFC 3339 section 5.6) and ajv-formats 3.0.1 agree on all but two variants, which
  ajv-formats accepts and the RFC's grammar does not: a space in place of `T`, and an offset written without its colon.
- Asserting `format` changes five verdicts, all from valid to invalid: the case `timestamp-no-offset`, and variants with
  no offset, 30 February, Arabic-Indic digits, and a string that is not a date. No other record payload changes, and
  `timestamp-not-utc` stays valid either way.

## The mutation sweep

After the cases, `run.mjs` re-scores its own checks with each one changed in turn and requires that exactly the cases
resting on it stop matching: each of the eight checks turned off, each digest computed over the wrong bytes, `format`
asserted, and each of the schema's five enums dropped from an in-memory copy of it. Every enum has a case that depends on
it, and only that case. A pass therefore cannot come from a check that never fires.

## What it checks, and what it does not

It checks that the gate signed the record with the pinned key, that no record in a log was rewritten once a later record
linked it, that the record conforms to the published schema, that it names that schema by version and by the digest of
its bytes, that its action digest names the action presented, that the approver is not the agent, and that a standing
grant it relies on is recorded.

It does not check:

- That anything a record says is true. A signed record is the gate's statement.
- That a log is complete. A chain shows a record rewritten or removed between the records a log holds, not records
  missing from its end (see `../timeliness/` for what bounds that).
- The rules MI-24 states that v1.1.0 has no field for (the next section).
- Another verifier's checks. The codes and exit statuses are `@veritasacta/verify`'s; another verifier is held to the
  verdict alone.

## Questions for the schema's next version

The schema settles most of what an earlier draft of these vectors had to guess: the value sets, the shape of
`suspension_trigger_state`, non-negative amounts, the encoding of `resolved_action_digest`, `rollback_token` for the
idempotency key, the members that name the schema, and an approver on every record. What it leaves open:

1. **No field for the decision's outcome.** MI-24's Minimum Evidence Set asks for "the decision including any
   modification linkage". v1.1.0 has no member for approved, rejected, modified or released (the v1.0 specification
   listed `decision` and `approvals[]`). So `trip-record` and `release-while-tripped` share a shape, and two of the three
   contradictions MI-24 names ("an approval whose", "a release recorded while") cannot be keyed to the kind of record.
2. **UTC is not enforced.** `timestamp_utc` is a date-time, which accepts any offset even when asserted, and no offset at
   all when not. Only the description says UTC. A pattern ending in `Z` would settle both cases.
3. **No stated encoding for `schema_sha256`.** `resolved_action_digest` has a pattern (`sha256:` and lowercase hex);
   `schema_sha256` accepts any string, "not a digest" included.
4. **Status and trigger need not agree.** `TRIPPED` with `tripped_trigger` `NONE`, and `CLEAR` naming `ST-01`, both
   validate. What does `RESET` carry?
5. **`grant_id` is required even for `PER_ACTION_APPROVAL`.** What goes there when no standing grant applies? These
   vectors put the decision's own approval, prefixed `per-action:`, and resolve `grant_id` against recorded grants only
   for `STANDING_BOUNDED_GRANT` and `UNATTENDED_T2`.
6. **`DUAL_KEY_APPROVAL` with one `human_approver` object.** Where does the second key holder go?
7. **The v1.0 specification and the v1.1.0 schema disagree.** Section 3 of the specification says the canonical schema is
   published at the schema's URL, and lists other required fields (`record_id`, `agent_version`, `action_class`,
   `tier_at_time`, `owner`, `decision`, `approvals[]`, `record_hash` and more) and seven triggers. v1.1.0 requires
   MI-24's fields and five triggers. The tier names differ too: the specification's T1 is Act & Notify and its T3 Act
   Alone with Audit, where the schema has `T1_HUMAN_APPROVAL_REQUIRED` and `T3_PROHIBITED`. Which describes the published
   schema now?
8. **"(or gating mode)" against a tier-only enum.** MI-24 and the schema's description both write `autonomy_tier` (or
   gating mode), but the enum holds only the four tiers.
9. **`control_owner` is optional.** MI-24 names an accountable control owner, and the specification's Own pillar
   required an `owner`.
10. **The `$id` fragment.** Draft 2020-12 does not allow a non-empty fragment in `$id`, and ajv 8.20.0 will not compile
    the schema as published. The version could move into the path.
11. **MI-24's pattern names.** MI-24 names user confirmation, maker-checker or four-eyes, and dual authorization; the
    enum has no value for the first two. `UNATTENDED_T2` sits under `human_approver` though no human approves the action.
12. **Empty and open members.** `decision_id`, `agent_id`, `principal_id` and `grant_id` may be empty strings, and
    `trigger_evidence` defines no members, though MI-24 lists the evidence each trigger needs.

## Why the schema check has no dependencies

`lib.mjs` validates with about sixty lines of its own, not a JSON Schema library with a lockfile:

- Every other part of `verifier-vectors/` runs on Node alone beside the verifier under test, and vectors offered to
  another project should be quick to read and rerun.
- The schema uses eight assertion keywords (`type`, `required`, `properties`, `items`, `enum`, `const`, `pattern`,
  `minimum`) and one annotation, `format`. `checkSchema()` refuses any other keyword before a record is read, so a later
  version that adds one fails loudly rather than going unchecked.
- `scripts/crosscheck-ajv.mjs` holds it to ajv, as above, and CI requires the agreement. The patterns it reads are the
  schema's own; the date-time check spells digits `[0-9]`, which is why Arabic-Indic digits fail it as they fail
  ajv-formats.

## Relation to the agent-audit-record corpus and the mi-21 run

MI-24's Conformance bullet names two carriers for the same approval evidence. The first is the signed agent audit record
of draft-gilda-wimse-agent-audit-record-02, with the agent-audit-record corpus of agent-evidence-vectors 0.18.1 (68
records: 17 valid, 49 invalid, and 2 the draft does not settle), maintained by @astrogilda. That corpus tests a verifier
of the audit record, whose members differ from the decision record's: MI-24's mapping table gives the closest fields and
leaves `model_version`, `autonomy_tier`, the blast-radius metrics, `evidence_refs` and `rollback_token` without one. These
vectors cover the second carrier, the "Alternatively" path: the decision record as the signed payload of a
draft-farley-acta-signed-receipts receipt. From that corpus they take the convention for a case the text does not
decide.

The mi-21 receipt-signature run that the bullet names, proposed in
[#394](https://github.com/finos/ai-governance-framework/pull/394), replays the 25 Acta receipts of agent-evidence-vectors'
`vectors-receipt-signature` corpus through a verifier, as `../agent-evidence-vectors/` does here. It tests the verifier's
signature, key-window and chain verdicts, and reads no record field. These vectors use the same verifier for the receipt
and add checks (b) to (d).

## Keys

| Role | kid | Seed | Public key | In a key set |
|---|---|---|---|---|
| Gate (issuer) | `test:mi24-gate:ed25519` | `00..10` | `index.json` `issuer.public_key_hex` | `issuer-jwks.json`, valid from 2026-01-01T00:00:00Z until 2027-01-01T00:00:00Z |
| The agent's own key | `test:mi24-agent:ed25519` | `00..11` | `index.json` `other_keys` | none: it signs only `records/unexpected-signer.json` |

Both are published test keys derived from fixed seeds that are used nowhere else in this repository. They MUST NOT be
reused. The canonicalization in `../../evidence-predicate/lib.mjs` is sorted-key JSON with no whitespace, which is RFC
8785 for the values these files hold.
