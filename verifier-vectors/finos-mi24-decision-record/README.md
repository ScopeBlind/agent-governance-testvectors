# FINOS MI-24 decision records carried as Acta receipts: a draft

**Status: a DRAFT, offered for the follow-up to MI-24 in
[finos/ai-governance-framework](https://github.com/finos/ai-governance-framework)
([#412](https://github.com/finos/ai-governance-framework/pull/412)). FINOS owns the MI-24 decision record and has not
adopted, reviewed or endorsed anything here. The schema is a draft for FINOS to adopt, change or reject.**

**Provenance:** written by ScopeBlind, which maintains draft-farley-acta-signed-receipts and `@veritasacta/verify`,
with AI coding agents (Claude). It is the format author's own work, not an independent evaluation.

## Why it exists

MI-24 (Human-in-the-Loop Action Approval Gate), as #412 has it at head `490d0fd7`, asks that each decision envelope be
serialized against a versioned JSON Schema capturing at minimum the members it lists, and that each record name its
schema by version and by the SHA-256 digest of the schema's bytes. MI-24 publishes no schema file. Its Conformance
bullet says a record may instead travel as the signed payload of a draft-farley-acta-signed-receipts decision receipt,
which "allows mi-24 approval records to be checked by the same mi-21 receipt-signature conformance run". That run checks
a receipt's signature, key window and chain link. It reads no MI-24 member.

This folder is one way to make the stronger sentence true: a draft schema for the members MI-24 lists, Acta receipts
whose signed payload is one MI-24 record each, and a runner that checks the receipt with the published verifier and
then the record. `index.json` pins the MI-24 text it encodes: the file at #412's head, with its SHA-256.

## Run

From the repository root:

```bash
# The pinned verifier, and ajv for the optional cross-check, in a temporary prefix (.verify/ is gitignored)
npm install --prefix .verify --no-save --no-audit --no-fund @veritasacta/verify@0.11.1 ajv@8.20.0
VERIFY_CMD="$PWD/.verify/node_modules/.bin/verify" node verifier-vectors/finos-mi24-decision-record/run.mjs
node verifier-vectors/finos-mi24-decision-record/scripts/crosscheck-ajv.mjs .verify

# Or through npx, with nothing installed
node verifier-vectors/finos-mi24-decision-record/run.mjs

# Rewrite every file but the schema, or check that each is current
node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs
node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs --check
```

`run.mjs` exits 0 when every case matched and every mutation was caught, 1 otherwise, and 77 when the pinned verifier
cannot run here. On `@veritasacta/verify` 0.11.1 (published with npm provenance) it reports `27 passed, 0 failed`: 17
cases, then 10 mutations. CI runs the generator check, the runner and the cross-check on Node 20 and 22.

## What is here

| Path | What it holds |
|---|---|
| `schema/mi24-decision-record-0.1.0-draft.schema.json` | The draft schema, JSON Schema 2020-12, written by hand. Records name it by the SHA-256 of its bytes, and `.gitattributes` stops git rewriting them. |
| `records/` | 16 receipts and 2 logs of two receipts each, signed with seeded test keys. |
| `actions/` | The resolved actions that `resolved_action_digest` is checked against. |
| `issuer-jwks.json` | The pinned gate key: the only key the verifier is given. |
| `grants.json` | The recorded standing approvals that a `grant_id` resolves against. |
| `index.json` | Every case: its parent, its one change, the expected result of each check, and what the verifier reports. |
| `lib.mjs` | The schema check and the MI-24 rules, with no dependencies. |
| `run.mjs` | The runner. |
| `scripts/generate.mjs` | Writes every file but the schema. `--check` fails on a stale file. |
| `scripts/crosscheck-ajv.mjs` | Runs the payloads through ajv beside `lib.mjs`. |

## The receipts

Each receipt has the envelope shape of draft-farley-acta-signed-receipts and is signed with Ed25519 over JCS(payload).
The payload is one MI-24 record plus the receipt's own members (Section 2.2): `type`, `issuer_id`, `issued_at`, and
`previousReceiptHash` when the record follows another (Section 6.7). `type` is
`x-agent-governance-testvectors:mi24-decision-record`, a placeholder in this repository's namespace. The schema allows
the receipt's members because MI-24 lists what a record captures at minimum.

Three records are parents, and every other case makes one change to one of them:

- `gated-approval`: a per-action maker-checker approval of a 25,000 USD payment, with `grant_id` null.
- `standing-approval-chain`, line 2: a ticket released under a recorded standing approval, linked to the approval.
- `trip-record-no-approver`: an ST-01 trip record, with `human_approver` null.

Member values (tiers, patterns, trigger states, identifiers) are illustrative. MI-24 defines none of them.

## The checks

| Check | Decided by | Passes when |
|---|---|---|
| `signature` | `@veritasacta/verify` 0.11.1 | The signature verifies under the pinned key set, over a signing input with no signature member (Section 6.6). |
| `key` | the verifier's report | The record names the pinned gate key (`issuer_id` is `signature.kid`), the verifier resolved that key from the pinned set, and the signed `issued_at` is inside its window. |
| `chain` | `verify --replay-chain` | In a log, each record's `previousReceiptHash` is the Section 6.7 link of the record before it. |
| `schema` | `lib.mjs` | The payload validates against the draft schema. |
| `schema_digest` | `lib.mjs` | The record names the schema's version, and the SHA-256 of the schema file's bytes. |
| `action_digest` | `lib.mjs` | `resolved_action_digest` is the SHA-256 of the RFC 8785 bytes of the action supplied with the case. |
| `approver_not_agent` | `lib.mjs` | `human_approver.principal_id` is not `agent_id`. |
| `grant_recorded` | `lib.mjs` | `human_approver.grant_id`, when not null, names a standing approval in `grants.json`. |

A check that does not apply to a record is `not_run`. The verdict combines the checks as Section 5.3 of the -04 editor's
copy (VeritasActa/drafts#6) does: invalid if a check ran and failed, undecidable if none failed and one could not
decide, otherwise valid.

After the cases, `run.mjs` turns each check off in turn, then computes each digest over the wrong bytes, and requires
that exactly the cases resting on it stop matching. A pass therefore cannot come from a check that never fires.

## The cases

| Case | Change from its parent | Checks that do not pass | Expected | The verifier on the receipt |
|---|---|---|---|---|
| `gated-approval` | parent | none | ACCEPT | valid |
| `standing-approval-chain` | parent: two records, linked | none | ACCEPT | valid, one chain |
| `signature-altered` | last hex digit of the signature | signature | REJECT | invalid, `invalid_signature` |
| `field-changed-after-signing` | `blast_radius_usd` 25000 to 2500, signature kept | signature | REJECT | invalid, `invalid_signature` |
| `unexpected-signer` | signed with the agent's own key, which it names | signature (undecidable), key | REJECT | undecidable, exit 2, `jwks_fetch_failed` |
| `broken-chain` | line 1 rewritten and signed again after line 2 linked it | chain | REJECT | invalid, `chain_break` on line 2 |
| `missing-decision-id` | `decision_id` removed | schema | REJECT | valid |
| `missing-human-approver` | `human_approver` removed | schema | REJECT | valid |
| `approver-is-agent` | `principal_id` set to `agent_id` | approver_not_agent | REJECT | valid |
| `grant-not-recorded` | a `grant_id` no recorded grant carries | grant_recorded | REJECT | valid |
| `action-digest-mismatch` | none to the receipt; the action presented pays another account | action_digest | REJECT | valid |
| `schema-digest-mismatch` | the digest of the schema's RFC 8785 form, not its bytes | schema_digest | REJECT | valid |
| `schema-version-mismatch` | `schema_version` 0.2.0-draft, digest unchanged | schema, schema_digest | REJECT | valid |
| `timestamp-not-utc` | the same instant written at +11:00 | schema | REJECT | valid |
| `evidence-refs-not-array` | one string instead of an array | schema | REJECT | valid |
| `trip-record-no-approver` | parent | schema | unsettled | valid |
| `release-while-tripped` | `suspension_trigger_state` set to "ST-01 tripped" | none | unsettled | valid |

Where the verifier reports a valid receipt and the case expects REJECT, the receipt is sound and the record is not:
that is the gap between the mi-21 run and an MI-24 check.

### Two cases MI-24 does not settle

As in the agent-audit-record corpus of agent-evidence-vectors, an unsettled case carries no expected verdict. It lists
the readings a conforming verifier may take, and `index.json` gives the reason for each.

- `trip-record-no-approver`: Trip and Reset Records has every trip write its own decision record, and a breaker trips
  automatically, with no human decision. But the Machine-Readable Decision Record Schema bullet lists `human_approver`
  among the members every record captures. REJECT (the draft schema's reading) and ACCEPT both conform.
- `release-while-tripped`: Checkable Decision Records calls a release recorded while `suspension_trigger_state` names a
  tripped trigger a contradiction. No member MI-24 lists marks a record as a release, though, and MI-24 defines no value
  that means tripped, so nothing a verifier can read establishes it. ACCEPT (what this runner can reach) and REJECT both
  conform.

## What it checks, and what it does not

It checks that the gate signed the record with the pinned key, that no record in a log was rewritten once a later
record linked it, that the record has the members MI-24 lists in the forms this draft gives them, that it names this
schema by version and by the digest of its bytes, that its action digest is the digest of the action presented, that the
approver is not the agent, and that a named grant is a recorded one.

It does not check:

- That anything a record says is true. A signed record is the gate's statement.
- That a log is complete. A chain shows a record rewritten or removed between the records a log holds, not records
  missing from its end (see `../timeliness/` for what bounds that).
- Anything the next section lists as beyond MI-24's members.
- That `timestamp_utc` names a day that exists, or how it relates to the receipt's `issued_at`.
- Another verifier's MI-24 checks. The codes and exit statuses are `@veritasacta/verify`'s; another verifier is held to
  the verdict alone.

## What MI-24's text does not let a record show

These rules are in MI-24 but were not encoded, because doing so would mean inventing a member or a meaning:

- A release recorded while a trigger is tripped (`release-while-tripped`): no member marks a release, and no value means
  tripped.
- Whether a record with no human decision may carry a null or absent `human_approver` (`trip-record-no-approver`).
- The reset rules of Trip and Reset Records. A reset records the operator who reconciled state, re-verifies `grant_id`
  and `policy_version`, and keeps rolling exposure counters. No member marks a reset or names that operator, and a
  rolling total can fall as its window moves, so a lower `cumulative_24h_usd` after a reset does not by itself show a
  fresh quota.
- The ST-01 to ST-05 thresholds. "For example `>= 80%`" is an example, and the ceiling is not a member.
- Deadlines and expiry, limits that policy makes non-waivable, a release the gate could not evaluate, and the
  `outcome-unknown` state. MI-24 describes each one, but no member in the schema's minimum carries them.
- Maker-checker and dual authorization beyond "not the agent". There is no requester member, and one approver object.
- The bounds of a standing grant (scope, argument constraints, environment, expiry, revocation) at release time.
- That the approver was authenticated, held delegated authority, or saw the resolved action.

## Open questions for FINOS

Each is a choice this draft had to make. None is settled by it.

1. **Is there a schema already?** MI-24's Additional Resources cites the A-DoA framework v1.0 (Swosti Panda, CC BY 4.0,
   [10.5281/zenodo.23275115](https://doi.org/10.5281/zenodo.23275115)). Its title names autonomy tiers (T0 to T3),
   suspension triggers and decision records, and MI-24's link text names a decision-record JSON Schema. This draft was
   written from MI-24's text alone, without that document. If its schema is the one MI-24 means, publishing it as a file
   would settle most of what follows, and this draft should be compared with it member by member or withdrawn.
2. **How a record names its schema.** The members (`schema_version` and `schema_digest` here), the digest's form
   (`sha256:` and lowercase hex here), and its preimage. This draft reads "the schema's bytes" as the published file's
   exact bytes, because MI-24 names RFC 8785 for the action digest and not for this one. Bytes need a fixed published
   file, line endings included, and a FINOS `$id`.
3. **What kind of record it is.** No member MI-24 lists says whether a record is an approval, a rejection, a
   modification, an expiry, a release, a trip or a reset, yet two of the three contradictions MI-24 names turn on it.
   Should the schema carry the decision, and the lifecycle state of Single-Effect Resolution?
4. **The Minimum Evidence Set beside the schema.** That bullet also asks for the rule that triggered the gate, the
   session identity, the decision with any modification linkage, the lifecycle transitions with their timestamps, and
   a correlation identifier into the execution trace. The schema's minimum lists none of them. Should it, or is the
   record one part of that set?
5. **Value sets.** Is the "gating mode" of `autonomy_tier` (or gating mode) the same member or another one, and are
   A-DoA's tiers its values? Should `oversight_pattern` have tokens for the patterns Key Principles and Routing to the
   Right Human describe? Does `action_type` have values? All are non-empty strings here.
6. **`suspension_trigger_state`.** Its JSON type (a string or an object here), its value when no trigger is tripped,
   and the members that carry each trigger's evidence. Trip and Reset Records says what that evidence is, not how it is
   written.
7. **`human_approver`.** One object names one principal: how does dual authorization, or N-of-M, name two or more?
   Should the requester appear, so a verifier can check that the checker is not the requester as well as not the agent?
   What does a record with no human decision, such as a trip or an expiry, carry?
8. **`grant_id` for a per-action decision.** It is null here. MI-24 does not say whether it is null, absent or another
   value.
9. **The money members.** JSON numbers here, and a decimal string would avoid binary rounding. May they be negative
   (allowed here)? Does `cumulative_24h_usd` include this action?
10. **`timestamp_utc`.** RFC 3339 is this draft's reading, with any spelling of UTC (`Z`, `z`, `+00:00`, `-00:00`). One
    spelling would make equal instants equal strings. When a record travels in an Acta receipt, should it equal the
    receipt's `issued_at` (one second later here)?
11. **"An idempotency or `rollback_token`".** The first one's member name (`idempotency_key` here, after the
    idempotency key of Be Honest About Execution Semantics), and whether at least one is required (here) or both.
12. **`evidence_refs`.** The form of a reference, and whether the list may be empty. It may be here: ST-04 treats a
    missing required reference as a trip, not as an invalid record.
13. **Comparing identities.** `principal_id` and `agent_id` are compared as exact strings here. Should a verifier resolve
    an identity first?
14. **The grant record.** What a recorded standing approval is and how a verifier gets it. `grants.json` holds
    identifiers only. Should a release also be checked against the grant's scope, environment and expiry?
15. **Carriage in an Acta receipt.** The receipt `type` (a placeholder here), whether the record is the payload (here)
    or one member of it, and whose key signs. Here it is the gate's: MI-24's non-repudiation sentence allows an
    institutional signing key or the approver's identity.

## Why the schema check has no dependencies

`lib.mjs` validates with about forty lines of its own, not a JSON Schema library with a lockfile, for three reasons:

- Every other part of `verifier-vectors/` runs on Node alone beside the verifier under test, and a draft offered to
  another project should be quick to read and rerun.
- The draft uses nine assertion keywords (`type`, `required`, `properties`, `items`, `anyOf`, `const`, `minLength`,
  `minProperties`, `pattern`). `checkSchema()` refuses any other keyword before a record is read, so an edit that adds
  one fails loudly rather than going unchecked.
- Nothing in the schema depends on this code. `scripts/crosscheck-ajv.mjs` runs the 20 record payloads and 20 variants,
  which reach the keywords no case refuses on, through ajv 8.20.0's draft 2020-12 validator. Strict mode is on, less its
  `strictRequired` lint, which is ajv's own style rule. CI requires all 40 to agree. The patterns spell digits `[0-9]`,
  not `\d`, so that an engine whose `\d` matches other scripts' digits agrees too: one variant carries Arabic-Indic
  digits.

A FINOS adopter would validate with a full 2020-12 validator.

## Relation to the agent-audit-record corpus and the mi-21 run

MI-24's Conformance bullet names two carriers for the same approval evidence. The first is the signed agent audit record
of draft-gilda-wimse-agent-audit-record-02, with the agent-audit-record corpus of agent-evidence-vectors 0.18.1 (68
records: 17 valid, 49 invalid, and 2 the draft does not settle), maintained by @astrogilda. That corpus tests a verifier
of the audit record, whose members differ from the decision record's: MI-24's mapping table gives the closest fields
and leaves `model_version`, `autonomy_tier`, the blast-radius metrics, `evidence_refs` and `rollback_token` without one.
This set covers the second carrier, the "Alternatively" path: the decision record as the signed payload of a
draft-farley-acta-signed-receipts receipt. From that corpus it takes the convention for a case the text does not
decide.

The mi-21 receipt-signature run that the bullet names, proposed in
[#394](https://github.com/finos/ai-governance-framework/pull/394), replays the 25 Acta receipts of agent-evidence-vectors'
`vectors-receipt-signature` corpus through a verifier, as `../agent-evidence-vectors/` does here. It tests the verifier's
signature, key-window and chain verdicts, and reads no MI-24 member. This set uses the same verifier for the receipt and
adds the MI-24 checks.

## Keys

| Role | kid | Seed | Public key | In a key set |
|---|---|---|---|---|
| Gate (issuer) | `test:mi24-gate:ed25519` | `00..10` | `index.json` `issuer.public_key_hex` | `issuer-jwks.json`, valid from 2026-01-01T00:00:00Z until 2027-01-01T00:00:00Z |
| The agent's own key | `test:mi24-agent:ed25519` | `00..11` | `index.json` `other_keys` | none: it signs only `records/unexpected-signer.json` |

Both are published test keys derived from fixed seeds that are used nowhere else in this repository. They MUST NOT be
reused. The canonicalization in `../../evidence-predicate/lib.mjs` is sorted-key JSON with no whitespace, which is RFC
8785 for the values these files hold.
