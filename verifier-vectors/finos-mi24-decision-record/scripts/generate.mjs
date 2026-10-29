#!/usr/bin/env node
// Deterministically generate the draft FINOS MI-24 decision record vectors: MI-24 decision records, each the signed
// payload of a draft-farley-acta-signed-receipts receipt.
//
//   node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs          write the files
//   node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs --check  fail if a file is stale
//
// A DRAFT for the follow-up to MI-24 in finos/ai-governance-framework (pull request 412), not adopted by FINOS. The
// schema in schema/ is written by hand and read here as bytes: every record names it by version and by the SHA-256 of
// those bytes, so any edit to the schema makes every record stale until this script runs again.
//
// Each case is one record from a parent with one change, or the parent itself. The expected result of every check is
// written out below by hand, not computed by the checks, so run.mjs cannot agree with itself by construction.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyPairFromSeed, sha256Hex, signHex, verifyHex } from '../../../evidence-predicate/lib.mjs'
import { checkSchema, sha256Prefixed } from '../lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

const SCHEMA_FILE = 'schema/mi24-decision-record-0.1.0-draft.schema.json'
const SCHEMA_VERSION = '0.1.0-draft'
const schemaBytes = fs.readFileSync(path.join(DIR, SCHEMA_FILE))
const schemaValue = JSON.parse(schemaBytes.toString('utf8'))
checkSchema(schemaValue)
if (schemaValue.properties.schema_version.const !== SCHEMA_VERSION) throw new Error(`${SCHEMA_FILE} declares another version`)
const SCHEMA_DIGEST = sha256Prefixed(schemaBytes)
// The same JSON value in RFC 8785 form: a digest of the schema, but not of its bytes. Used by one case only.
const SCHEMA_JCS_DIGEST = `sha256:${sha256Hex(schemaValue)}`

// Deterministic test keys. Public, and MUST NOT be reused. Their seeds are used nowhere else in this repository.
// The gate signs every record but one; the agent's own key signs only unexpected-signer.json and is in no key set here.
const GATE = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000010')
const GATE_KID = 'test:mi24-gate:ed25519'
const AGENT = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000011')
const AGENT_KID = 'test:mi24-agent:ed25519'
const WINDOW = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z' }
const x = (key) => Buffer.from(key.publicKeyHex, 'hex').toString('base64url')

// The resolved actions (MI-24 Bind the Decision to the Resolved Action): final recipient, amount and payload.
const ACTIONS = {
  'actions/payment.json': {
    tool: 'payments.transfer',
    arguments: { from_account: 'urn:example:account:operating-001', to_account: 'urn:example:account:vendor-7731', amount: '25000.00', currency: 'USD', reference: 'INV-20431' },
  },
  'actions/payment-modified.json': {
    tool: 'payments.transfer',
    arguments: { from_account: 'urn:example:account:operating-001', to_account: 'urn:example:account:vendor-9902', amount: '25000.00', currency: 'USD', reference: 'INV-20431' },
  },
  'actions/ticket.json': {
    tool: 'tickets.create',
    arguments: { queue: 'payables-reconciliation', title: 'Reconcile the payment for INV-20431', links: ['urn:example:decision:dec-20261027-0001'] },
  },
  'actions/payment-held.json': {
    tool: 'payments.transfer',
    arguments: { from_account: 'urn:example:account:operating-001', to_account: 'urn:example:account:vendor-4410', amount: '56000.00', currency: 'USD', reference: 'INV-20502' },
  },
}
const actionDigest = (file) => `sha256:${sha256Hex(ACTIONS[file])}`

// The receipt's own payload members (draft-farley-acta-signed-receipts Section 2.2) come first; the rest of the
// payload is the MI-24 record, in the order MI-24 lists its members, with the schema it names last.
const TYPE = 'x-agent-governance-testvectors:mi24-decision-record'
function receiptMembers(issuedAt, link) {
  const members = { type: TYPE, issuer_id: GATE_KID, issued_at: issuedAt }
  if (link !== undefined) members.previousReceiptHash = link
  return members
}
const NAMED = { schema_version: SCHEMA_VERSION, schema_digest: SCHEMA_DIGEST }
const AGENT_ID = 'agent:payables-assistant'
const COMMON = { agent_id: AGENT_ID, model_version: 'example-model-2026-09', policy_version: 'agent-gate-policy@2026.10.2' }

function sign(payload, key = GATE, kid = GATE_KID) {
  const sig = signHex(payload, key.privateKey)
  if (!verifyHex(payload, sig, key.publicKeyHex)) throw new Error('a generated signature does not verify')
  return { payload, signature: { alg: 'EdDSA', kid, sig } }
}
const without = (value, member) => Object.fromEntries(Object.entries(value).filter(([k]) => k !== member))

// A: a per-action maker-checker approval of a payment. No standing approval, so grant_id is null.
const A = {
  ...receiptMembers('2026-10-27T22:14:06Z'),
  decision_id: 'dec-20261027-0001',
  timestamp_utc: '2026-10-27T22:14:05Z',
  ...COMMON,
  autonomy_tier: 'per-action approval',
  action_type: 'payments.transfer',
  resolved_action_digest: actionDigest('actions/payment.json'),
  blast_radius_usd: 25000,
  cumulative_24h_usd: 25000,
  evidence_refs: ['urn:example:invoice:INV-20431', 'urn:example:sanctions-screen:ss-4471'],
  human_approver: { principal_id: 'user:treasury-checker-02@example.com', oversight_pattern: 'maker-checker', grant_id: null },
  suspension_trigger_state: 'no trigger tripped',
  idempotency_key: 'idem-payables-20261027-0001',
  ...NAMED,
}
const rA = sign(A)

// B: a ticket released under a recorded standing approval, appended after A and linked to it (Section 6.7).
const B = {
  ...receiptMembers('2026-10-27T22:20:02Z', `sha256:${sha256Hex(rA)}`),
  decision_id: 'dec-20261027-0002',
  timestamp_utc: '2026-10-27T22:20:01Z',
  ...COMMON,
  autonomy_tier: 'standing approval',
  action_type: 'tickets.create',
  resolved_action_digest: actionDigest('actions/ticket.json'),
  blast_radius_usd: 0,
  cumulative_24h_usd: 25000,
  evidence_refs: ['urn:example:decision:dec-20261027-0001'],
  human_approver: { principal_id: 'user:payables-operator-07@example.com', oversight_pattern: 'user confirmation', grant_id: 'grant-tickets-create-20261027-a' },
  suspension_trigger_state: 'no trigger tripped',
  rollback_token: 'rollback-tickets-20261027-0002',
  ...NAMED,
}
const rB = sign(B)

// T: an ST-01 trip record. The proposed payment would take the rolling total to 81 percent of the ceiling, and the
// breaker trips with no human decision. suspension_trigger_state names what Trip and Reset Records asks of ST-01; the
// member names inside it are this draft's, since MI-24 defines none.
const T = {
  ...receiptMembers('2026-10-27T23:41:10Z'),
  decision_id: 'dec-20261027-0003',
  timestamp_utc: '2026-10-27T23:41:09Z',
  ...COMMON,
  autonomy_tier: 'bounded unattended execution',
  action_type: 'payments.transfer',
  resolved_action_digest: actionDigest('actions/payment-held.json'),
  blast_radius_usd: 56000,
  cumulative_24h_usd: 81000,
  evidence_refs: ['urn:example:invoice:INV-20502'],
  human_approver: null,
  suspension_trigger_state: { trigger: 'ST-01', rolling_total_usd: 81000, ceiling_usd: 100000, policy_version: COMMON.policy_version },
  idempotency_key: 'idem-payables-20261027-0003',
  ...NAMED,
}

const lastNibbleFlipped = (hex) => hex.slice(0, -1) + (parseInt(hex.slice(-1), 16) ^ 1).toString(16)
const RECEIPTS = new Map([
  ['records/gated-approval.json', rA],
  ['records/standing-approval.json', rB],
  ['records/gated-approval-rewritten.json', sign({ ...A, human_approver: { ...A.human_approver, principal_id: 'user:treasury-checker-05@example.com' } })],
  ['records/signature-altered.json', { ...rA, signature: { ...rA.signature, sig: lastNibbleFlipped(rA.signature.sig) } }],
  ['records/field-changed-after-signing.json', { payload: { ...A, blast_radius_usd: 2500 }, signature: rA.signature }],
  ['records/unexpected-signer.json', sign({ ...A, issuer_id: AGENT_KID }, AGENT, AGENT_KID)],
  ['records/missing-decision-id.json', sign(without(A, 'decision_id'))],
  ['records/missing-human-approver.json', sign(without(A, 'human_approver'))],
  ['records/approver-is-agent.json', sign({ ...A, human_approver: { ...A.human_approver, principal_id: AGENT_ID } })],
  ['records/grant-not-recorded.json', sign({ ...B, human_approver: { ...B.human_approver, grant_id: 'grant-tickets-create-20261027-b' } })],
  ['records/schema-digest-mismatch.json', sign({ ...A, schema_digest: SCHEMA_JCS_DIGEST })],
  ['records/schema-version-mismatch.json', sign({ ...A, schema_version: '0.2.0-draft' })],
  ['records/timestamp-not-utc.json', sign({ ...A, timestamp_utc: '2026-10-28T09:14:05+11:00' })],
  ['records/evidence-refs-not-array.json', sign({ ...A, evidence_refs: 'urn:example:invoice:INV-20431' })],
  ['records/trip-record-no-approver.json', sign(T)],
  ['records/release-while-tripped.json', sign({ ...B, suspension_trigger_state: 'ST-01 tripped' })],
])

// Logs read in order, one receipt per line (verify --replay-chain).
const SEQUENCES = new Map([
  ['records/standing-approval-chain.jsonl', ['records/gated-approval.json', 'records/standing-approval.json']],
  ['records/broken-chain.jsonl', ['records/gated-approval-rewritten.json', 'records/standing-approval.json']],
])

// The expected result of each check. signature and key are @veritasacta/verify's (pass, fail, undecidable); the rest
// are run.mjs's own (pass, fail, not_run). Most cases pass every check but one, so each case writes only its changes.
const PASSING = {
  signature: 'pass', key: 'pass', chain: 'not_run', schema: 'pass', schema_digest: 'pass',
  action_digest: 'pass', approver_not_agent: 'pass', grant_recorded: 'not_run',
}
const checks = (changes = {}) => ({ ...PASSING, ...changes })
const VALID = { verdict: 'ACCEPT', outcome: 'valid' }
const INVALID = { verdict: 'REJECT', outcome: 'invalid' }
const RECEIPT_VALID = { outcome: 'valid', exit: 0, code: null }
const PAY = 'actions/payment.json'
const TICKET = 'actions/ticket.json'

const MDRS = 'Machine-Readable Decision Record Schema'
const CDR = 'Checkable Decision Records'
const CASES = [
  {
    id: 'gated-approval', kind: 'accept', check: 'alone', file: 'records/gated-approval.json', actions: [PAY],
    parent: null, change: null,
    expected: { ...VALID, checks: checks() }, verify: RECEIPT_VALID, mi24: `${MDRS}; ${CDR}`,
    note: 'A per-action maker-checker approval of a 25,000 USD payment. It carries every member MI-24 lists, grant_id is null because no standing approval applies, it names the schema by version and by the digest of its bytes, and its resolved_action_digest is the digest of the action supplied.',
  },
  {
    id: 'standing-approval-chain', kind: 'accept', check: 'sequence', file: 'records/standing-approval-chain.jsonl',
    sequence: SEQUENCES.get('records/standing-approval-chain.jsonl'), line: 2, actions: [PAY, TICKET],
    parent: null, change: null,
    expected: { ...VALID, checks: checks({ chain: 'pass', grant_recorded: 'pass' }) },
    verify: { ...RECEIPT_VALID, chains: 1, chain_breaks: 0 }, mi24: 'Record the Grant as Approval Evidence; Tamper-Evidence vs. Non-repudiation; Conformance (informative)',
    note: 'The approval above, then a ticket released under a recorded standing approval, whose previousReceiptHash is the link to the approval: one chain. The release names its grant, so it is distinguishable from a per-action decision, and it carries rollback_token where the approval carries idempotency_key.',
  },
  {
    id: 'signature-altered', kind: 'reject', check: 'alone', file: 'records/signature-altered.json', actions: [PAY],
    parent: 'gated-approval', change: 'The last hex digit of signature.sig changed.',
    expected: { ...INVALID, checks: checks({ signature: 'fail' }) },
    verify: { outcome: 'invalid', exit: 1, code: 'invalid_signature' }, mi24: 'Tamper-Evidence vs. Non-repudiation',
    note: 'The record is untouched and every MI-24 check passes; the signature does not verify under the pinned gate key.',
  },
  {
    id: 'field-changed-after-signing', kind: 'reject', check: 'alone', file: 'records/field-changed-after-signing.json', actions: [PAY],
    parent: 'gated-approval', change: 'blast_radius_usd changed from 25000 to 2500 after signing, the signature kept.',
    expected: { ...INVALID, checks: checks({ signature: 'fail' }) },
    verify: { outcome: 'invalid', exit: 1, code: 'invalid_signature' }, mi24: 'Tamper-Evidence vs. Non-repudiation',
    note: 'The changed record is still well formed, so every MI-24 check passes on it. Only the signature shows that a member changed after signing.',
  },
  {
    id: 'unexpected-signer', kind: 'reject', check: 'alone', file: 'records/unexpected-signer.json', actions: [PAY],
    parent: 'gated-approval', change: 'Signed with the agent\'s own key, which signature.kid and issuer_id name.',
    expected: { ...INVALID, checks: checks({ signature: 'undecidable', key: 'fail' }) },
    verify: { outcome: 'undecidable', exit: 2, code: 'jwks_fetch_failed' }, mi24: 'Tamper-Evidence vs. Non-repudiation',
    note: 'A signature that verifies under the key it names, the agent\'s. The relying party pinned the gate\'s key, and MI-24 has non-repudiation rest on an institutional signing key or the approver\'s identity. Holding only the pinned key set, the verifier cannot check the signature (undecidable, exit 2), and the key check fails because the record names a key the pinned set does not hold, so the record is invalid.',
  },
  {
    id: 'broken-chain', kind: 'reject', check: 'sequence', file: 'records/broken-chain.jsonl',
    sequence: SEQUENCES.get('records/broken-chain.jsonl'), line: 2, actions: [PAY, TICKET],
    parent: 'standing-approval-chain', change: 'Line 1 rewritten after line 2 was appended: another approver named, and the record signed again with the gate key.',
    expected: { ...INVALID, checks: checks({ chain: 'fail', grant_recorded: 'pass' }) },
    verify: { outcome: 'invalid', exit: 1, code: 'chain_break', chains: 1, chain_breaks: 1 }, mi24: 'Tamper-Evidence vs. Non-repudiation; Conformance (informative)',
    note: 'Both records verify under the gate key and pass every MI-24 check. Line 2 still links to the approval as first written, so the rewrite shows even to a holder of the gate key: the append-only property the Conformance bullet gives the Acta link.',
  },
  {
    id: 'missing-decision-id', kind: 'reject', check: 'alone', file: 'records/missing-decision-id.json', actions: [PAY],
    parent: 'gated-approval', change: 'decision_id removed, then signed.',
    expected: { ...INVALID, checks: checks({ schema: 'fail' }) }, verify: RECEIPT_VALID, mi24: MDRS,
    note: 'The receipt verifies; the record lacks a member MI-24 lists.',
  },
  {
    id: 'missing-human-approver', kind: 'reject', check: 'alone', file: 'records/missing-human-approver.json', actions: [PAY],
    parent: 'gated-approval', change: 'human_approver removed, then signed.',
    expected: { ...INVALID, checks: checks({ schema: 'fail', approver_not_agent: 'not_run' }) }, verify: RECEIPT_VALID, mi24: `${MDRS}; Minimum Evidence Set`,
    note: 'A gated payment approval that names no approver. MI-24 lists human_approver among the members a record captures at minimum, and its Minimum Evidence Set needs the approver identity for every gated action.',
  },
  {
    id: 'approver-is-agent', kind: 'reject', check: 'alone', file: 'records/approver-is-agent.json', actions: [PAY],
    parent: 'gated-approval', change: 'human_approver.principal_id set to agent_id.',
    expected: { ...INVALID, checks: checks({ approver_not_agent: 'fail' }) }, verify: RECEIPT_VALID, mi24: `${CDR}; Named Oversight Pattern`,
    note: 'MI-24\'s first example of a record whose fields contradict each other. Every member is well formed, so the schema cannot see it.',
  },
  {
    id: 'grant-not-recorded', kind: 'reject', check: 'alone', file: 'records/grant-not-recorded.json', actions: [TICKET],
    parent: 'standing-approval-chain', change: 'Line 2\'s grant_id changed to one that no recorded standing approval carries, then signed.',
    expected: { ...INVALID, checks: checks({ grant_recorded: 'fail' }) }, verify: RECEIPT_VALID, mi24: `${CDR}; Record the Grant as Approval Evidence`,
    note: 'MI-24\'s second example: a grant_id that resolves to no recorded standing approval. grants.json stands for the institution\'s record of its grants, which the record itself cannot carry.',
  },
  {
    id: 'action-digest-mismatch', kind: 'reject', check: 'alone', file: 'records/gated-approval.json', actions: ['actions/payment-modified.json'],
    parent: 'gated-approval', change: 'The record is unchanged; the action presented for release pays another account.',
    expected: { ...INVALID, checks: checks({ action_digest: 'fail' }) }, verify: RECEIPT_VALID, mi24: `${CDR}; Bind the Decision to the Resolved Action`,
    note: 'The same receipt as gated-approval, byte for byte. The approval was granted for one version of the action; the action presented has another to_account, so its digest differs and the approval does not move to it.',
  },
  {
    id: 'schema-digest-mismatch', kind: 'reject', check: 'alone', file: 'records/schema-digest-mismatch.json', actions: [PAY],
    parent: 'gated-approval', change: 'schema_digest set to the SHA-256 of the schema in RFC 8785 form instead of its bytes, then signed.',
    expected: { ...INVALID, checks: checks({ schema_digest: 'fail' }) }, verify: RECEIPT_VALID, mi24: MDRS,
    note: 'The record names the right version and a digest of the same JSON value, but not of the bytes published. MI-24 names RFC 8785 for the action digest and the schema\'s bytes for this one.',
  },
  {
    id: 'schema-version-mismatch', kind: 'reject', check: 'alone', file: 'records/schema-version-mismatch.json', actions: [PAY],
    parent: 'gated-approval', change: 'schema_version set to 0.2.0-draft, then signed; schema_digest still names the bytes of 0.1.0-draft.',
    expected: { ...INVALID, checks: checks({ schema: 'fail', schema_digest: 'fail' }) }, verify: RECEIPT_VALID, mi24: MDRS,
    note: 'The two halves of the name disagree. The schema refuses any version but its own (const), and the digest check refuses a version other than the one whose bytes it hashed.',
  },
  {
    id: 'timestamp-not-utc', kind: 'reject', check: 'alone', file: 'records/timestamp-not-utc.json', actions: [PAY],
    parent: 'gated-approval', change: 'timestamp_utc written with a +11:00 offset (Sydney): the same instant, then signed.',
    expected: { ...INVALID, checks: checks({ schema: 'fail' }) }, verify: RECEIPT_VALID, mi24: MDRS,
    note: 'A valid RFC 3339 date-time for the same instant, but not in UTC.',
  },
  {
    id: 'evidence-refs-not-array', kind: 'reject', check: 'alone', file: 'records/evidence-refs-not-array.json', actions: [PAY],
    parent: 'gated-approval', change: 'evidence_refs a single string rather than an array, then signed.',
    expected: { ...INVALID, checks: checks({ schema: 'fail' }) }, verify: RECEIPT_VALID, mi24: MDRS,
    note: 'MI-24 writes evidence_refs[].',
  },
  {
    id: 'trip-record-no-approver', kind: 'unsettled', check: 'alone', file: 'records/trip-record-no-approver.json', actions: ['actions/payment-held.json'],
    parent: null, change: null,
    expected: { checks: checks({ schema: 'fail', approver_not_agent: 'not_run' }) },
    readings: [
      { verdict: 'REJECT', outcome: 'invalid', rationale: 'The Machine-Readable Decision Record Schema bullet lists human_approver among the members every record captures at minimum, and null names no principal_id, oversight_pattern or grant_id. The draft schema takes this reading.' },
      { verdict: 'ACCEPT', outcome: 'valid', rationale: 'Trip and Reset Records has each trip write its own decision record, and Deterministic Runtime De-Escalation trips a breaker automatically, with no human decision, so a trip record has no approver to name.' },
    ],
    verify: RECEIPT_VALID, mi24: `Trip and Reset Records; ${MDRS}`,
    note: 'An ST-01 trip: the proposed 56,000 USD payment would take the rolling total to 81,000 against a ceiling of 100,000. suspension_trigger_state names the trigger, the rolling total, the ceiling and the policy version, as Trip and Reset Records asks for ST-01, and human_approver is null.',
  },
  {
    id: 'release-while-tripped', kind: 'unsettled', check: 'alone', file: 'records/release-while-tripped.json', actions: [TICKET],
    parent: 'standing-approval-chain', change: 'Line 2\'s suspension_trigger_state set to "ST-01 tripped", then signed.',
    expected: { checks: checks({ grant_recorded: 'pass' }) },
    readings: [
      { verdict: 'REJECT', outcome: 'invalid', rationale: 'Checkable Decision Records names a release recorded while suspension_trigger_state names a tripped trigger as a record whose fields contradict each other. A verifier that reads "ST-01 tripped" as naming a tripped trigger, and a recorded grant_id as a release, refuses it.' },
      { verdict: 'ACCEPT', outcome: 'valid', rationale: 'MI-24 defines no value of suspension_trigger_state as naming a tripped trigger, and no member that says a record records a release, so the contradiction cannot be established from the members MI-24 lists. The draft schema and run.mjs take this reading: every check they can make passes.' },
    ],
    verify: RECEIPT_VALID, mi24: CDR,
    note: 'The release under standing approval, recorded with ST-01 named as tripped. A tripped breaker suspends unattended release, so MI-24 calls this record a contradiction, but the members it lists cannot show one.',
  },
]

const json = (value) => JSON.stringify(value, null, 2) + '\n'
const files = new Map()
files.set('issuer-jwks.json', json({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: GATE_KID, x: x(GATE), use: 'sig', ...WINDOW }] }))
files.set('grants.json', json({
  about: 'The recorded standing approvals the relying party resolves a grant_id against (MI-24 Record the Grant as Approval Evidence). MI-24 lists what a grant record persists (the grantor, scope and argument constraints, environment, grant and expiry times, any revocation) but defines no format for it, so each entry carries only the identifier the check reads.',
  recorded_standing_approvals: [{ grant_id: 'grant-tickets-create-20261027-a' }],
}))
for (const [name, value] of Object.entries(ACTIONS)) files.set(name, json(value))
for (const [name, r] of RECEIPTS) files.set(name, json(r))
for (const [name, members] of SEQUENCES) files.set(name, members.map((m) => JSON.stringify(RECEIPTS.get(m)) + '\n').join(''))
files.set('index.json', json({
  suite: 'finos-mi24-decision-record',
  status: 'DRAFT for the follow-up to MI-24 in finos/ai-governance-framework. Not adopted, reviewed or endorsed by FINOS, which owns the MI-24 decision record. Written by ScopeBlind, which maintains draft-farley-acta-signed-receipts and @veritasacta/verify, with AI coding agents: the format author\'s own work, not an independent evaluation.',
  mi24: {
    pull_request: 'https://github.com/finos/ai-governance-framework/pull/412',
    head: '490d0fd73e8f47f459698ee8c6e0843e0f9204cc',
    file: 'docs/_mitigations/mi-24_human-in-the-loop-action-approval-gate.md',
    file_sha256: '86e9d959d8a64c033144c9c1d66fb36ab7e83da4350cffacf103d8dd3462d08a',
  },
  profile: 'Each record is the signed payload of a draft-farley-acta-signed-receipts receipt (envelope shape, signed over JCS(payload)). The payload carries the receipt\'s own members (type, issuer_id, issued_at, and previousReceiptHash when chained) beside the MI-24 record.',
  record_type: TYPE,
  schema: { file: SCHEMA_FILE, version: SCHEMA_VERSION, sha256: SCHEMA_DIGEST },
  issuer: { kid: GATE_KID, public_key_hex: GATE.publicKeyHex, seed: '00..10', jwks: 'issuer-jwks.json', window: WINDOW },
  other_keys: { [AGENT_KID]: { public_key_hex: AGENT.publicKeyHex, seed: '00..11', note: 'The agent\'s own key. It signs only records/unexpected-signer.json and is in no key set here.' } },
  grants: 'grants.json',
  invocation: {
    alone: 'verify <file> --jwks issuer-jwks.json --mode receipt --json',
    sequence: 'verify --replay-chain <file> --jwks issuer-jwks.json --json',
  },
  checks: {
    signature: 'The receipt\'s signature, and its signing input (Section 6.6), under the pinned key set: @veritasacta/verify\'s checks.signature and checks.signing_input.',
    key: 'The receipt names the pinned gate key (issuer_id is signature.kid), the verifier resolved that key from the pinned key set, and the signed issued_at falls inside its window.',
    chain: 'In a sequence, each record\'s previousReceiptHash is the Section 6.7 link of the record before it (verify --replay-chain). A record checked alone has no predecessor to follow: not_run.',
    schema: 'The payload validates against the draft schema.',
    schema_digest: 'The record names the schema\'s version and "sha256:" plus the SHA-256 of the schema file\'s bytes.',
    action_digest: 'resolved_action_digest is "sha256:" plus the SHA-256 of the RFC 8785 bytes of the action supplied with the case.',
    approver_not_agent: 'human_approver.principal_id is not agent_id. not_run when the record names no human approver.',
    grant_recorded: 'human_approver.grant_id names a standing approval in grants.json. not_run when grant_id is null or absent.',
  },
  scoring: 'An accept or reject case conforms when the verdict and outcome equal expected. An unsettled case is one MI-24 does not decide: it carries no expected verdict, and a verifier conforms on it with any verdict its readings list, the convention of the agent-audit-record corpus in agent-evidence-vectors. expected.checks are the results of run.mjs\'s own checks, and verify the outcome, exit status and code @veritasacta/verify 0.11.1 reports for the receipt or, in a sequence, for the line named; another verifier is held to the verdict alone. The verdict combines the checks as Section 5.3 of the -04 editor\'s copy does: invalid if any check ran and failed, undecidable if none failed and one could not decide, otherwise valid.',
  counts: { accept: CASES.filter((c) => c.kind === 'accept').length, reject: CASES.filter((c) => c.kind === 'reject').length, unsettled: CASES.filter((c) => c.kind === 'unsettled').length },
  cases: CASES,
}))

let stale = 0
for (const [name, text] of files) {
  const target = path.join(DIR, name)
  if (CHECK) {
    const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null
    if (current !== text) { console.error(`stale: ${name}`); stale += 1 }
  } else {
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, text)
  }
}
if (CHECK) {
  if (stale) process.exit(1)
  console.log(`finos-mi24-decision-record vectors: ${files.size} files current`)
} else {
  console.log(`finos-mi24-decision-record vectors: wrote ${files.size} files to ${DIR}`)
}
