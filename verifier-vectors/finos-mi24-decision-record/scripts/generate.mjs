#!/usr/bin/env node
// Deterministically generate the FINOS MI-24 decision record vectors: records that follow the A-DoA Decision Record
// Schema v1.1.0 (Swosti Panda, CC BY 4.0), each the signed payload of a draft-farley-acta-signed-receipts receipt.
//
//   node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs          write the files
//   node verifier-vectors/finos-mi24-decision-record/scripts/generate.mjs --check  fail if a file is stale
//
// The schema in schema/ is the published file, vendored unchanged; this script refuses to run if a byte of it differs.
// Every record names it by version and by the SHA-256 of those bytes. Each case is one record from a parent with one
// change, or the parent itself. The expected result of every check is written out below by hand, not computed by the
// checks, so run.mjs cannot agree with itself by construction. Not reviewed or endorsed by FINOS or the schema's author.

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyPairFromSeed, sha256Hex, signHex, verifyHex } from '../../../evidence-predicate/lib.mjs'
import { checkSchema } from '../lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CHECK = process.argv.includes('--check')

const SCHEMA_FILE = 'schema/adoa-decision-record.schema.json'
const PUBLISHED_SHA256 = 'e5a4c6108e9df21863ec69ea80a3ee588ede3e8a27a74924305264bb7c5a549e'
const schemaBytes = fs.readFileSync(path.join(DIR, SCHEMA_FILE))
const hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex')
if (hex(schemaBytes) !== PUBLISHED_SHA256) throw new Error(`${SCHEMA_FILE} is not the published v1.1.0 schema, byte for byte`)
const schemaValue = JSON.parse(schemaBytes.toString('utf8'))
checkSchema(schemaValue)
const SCHEMA_VERSION = schemaValue.properties.schema_version.const
if (SCHEMA_VERSION !== '1.1.0') throw new Error(`${SCHEMA_FILE} declares version ${SCHEMA_VERSION}`)
// The schema states no encoding for schema_sha256. These vectors use lowercase hex, 64 characters, no prefix.
const SCHEMA_SHA256 = PUBLISHED_SHA256
// The same JSON value in RFC 8785 form: a digest of the schema, but not of its bytes. Used by one case only.
const SCHEMA_JCS_SHA256 = sha256Hex(schemaValue)

// Deterministic test keys. Public, and MUST NOT be reused. Their seeds are used nowhere else in this repository.
// The gate signs every record but one; the agent's own key signs only unexpected-signer.json and is in no key set here.
const GATE = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000010')
const GATE_KID = 'test:mi24-gate:ed25519'
const AGENT = keyPairFromSeed('0000000000000000000000000000000000000000000000000000000000000011')
const AGENT_KID = 'test:mi24-agent:ed25519'
const WINDOW = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z' }
const x = (key) => Buffer.from(key.publicKeyHex, 'hex').toString('base64url')

// The resolved actions and their arguments (MI-24 Bind the Decision to the Resolved Action).
const OPERATING = 'urn:example:account:operating-001'
const ACTIONS = {
  'actions/payment.json': {
    tool: 'payments.transfer',
    arguments: { from_account: OPERATING, to_account: 'urn:example:account:vendor-7731', amount: '25000.00', currency: 'USD', reference: 'INV-20431' },
  },
  'actions/payment-modified.json': {
    tool: 'payments.transfer',
    arguments: { from_account: OPERATING, to_account: 'urn:example:account:vendor-9902', amount: '25000.00', currency: 'USD', reference: 'INV-20431' },
  },
  'actions/ticket.json': {
    tool: 'tickets.create',
    arguments: { queue: 'payables-reconciliation', title: 'Reconcile the payment for INV-20431', links: ['urn:example:decision:dec-20261027-0001'] },
  },
  'actions/payment-held.json': {
    tool: 'payments.transfer',
    arguments: { from_account: OPERATING, to_account: 'urn:example:account:vendor-4410', amount: '14000.00', currency: 'USD', reference: 'INV-20502' },
  },
}
const actionDigest = (file) => `sha256:${sha256Hex(ACTIONS[file])}`

// The receipt's own payload members (draft-farley-acta-signed-receipts Section 2.2) come first; the rest of the payload
// is the A-DoA record, in the order the schema lists its members. The schema does not forbid other members.
const TYPE = 'x-agent-governance-testvectors:mi24-decision-record'
function receiptMembers(issuedAt, link) {
  const members = { type: TYPE, issuer_id: GATE_KID, issued_at: issuedAt }
  if (link !== undefined) members.previousReceiptHash = link
  return members
}
const AGENT_ID = 'agent:payables-assistant'
const COMMON = { agent_id: AGENT_ID, model_version: 'example-model-2026-09', policy_version: 'agent-gate-policy@2026.10.2' }
const NAMED = { schema_version: SCHEMA_VERSION, schema_sha256: SCHEMA_SHA256 }
const ALL_TRIGGERS = ['ST-01', 'ST-02', 'ST-03', 'ST-04', 'ST-05']
const CLEAR = { status: 'CLEAR', tripped_trigger: 'NONE', triggers_evaluated: ALL_TRIGGERS }
// trigger_evidence is an object the schema leaves open; these member names are the vectors' own.
const TRIPPED = {
  status: 'TRIPPED', tripped_trigger: 'ST-01', triggers_evaluated: ALL_TRIGGERS,
  trigger_evidence: { rolling_total_usd: 81000, ceiling_usd: 100000, policy_version: COMMON.policy_version },
}

function sign(payload, key = GATE, kid = GATE_KID) {
  const sig = signHex(payload, key.privateKey)
  if (!verifyHex(payload, sig, key.publicKeyHex)) throw new Error('a generated signature does not verify')
  return { payload, signature: { alg: 'EdDSA', kid, sig } }
}
const without = (value, member) => Object.fromEntries(Object.entries(value).filter(([k]) => k !== member))

// A: a per-action approval of a payment above the agent's T2 cap. The schema requires grant_id here too; with no
// standing grant to name, it carries the decision's own approval, prefixed per-action: (an open question).
const A = {
  ...receiptMembers('2026-10-27T22:14:06Z'),
  decision_id: 'dec-20261027-0001',
  timestamp_utc: '2026-10-27T22:14:05Z',
  ...COMMON,
  autonomy_tier: 'T1_HUMAN_APPROVAL_REQUIRED',
  action_type: 'payments.transfer',
  resolved_action_digest: actionDigest('actions/payment.json'),
  blast_radius_usd: 25000,
  cumulative_24h_usd: 25000,
  evidence_refs: ['urn:example:invoice:INV-20431', 'urn:example:sanctions-screen:ss-4471'],
  human_approver: { principal_id: 'user:treasury-checker-02@example.com', oversight_pattern: 'PER_ACTION_APPROVAL', grant_id: 'per-action:dec-20261027-0001' },
  suspension_trigger_state: CLEAR,
  rollback_token: 'idem-payables-20261027-0001',
  control_owner: 'AP Controller: user:ap-controller-01@example.com',
  ...NAMED,
}
const rA = sign(A)

// B: a ticket released under a recorded standing grant, appended after A and linked to it (Section 6.7).
const B = {
  ...receiptMembers('2026-10-27T22:20:02Z', `sha256:${sha256Hex(rA)}`),
  decision_id: 'dec-20261027-0002',
  timestamp_utc: '2026-10-27T22:20:01Z',
  ...COMMON,
  autonomy_tier: 'T2_BOUNDED_AUTO_EXECUTE',
  action_type: 'tickets.create',
  resolved_action_digest: actionDigest('actions/ticket.json'),
  blast_radius_usd: 0,
  cumulative_24h_usd: 25000,
  evidence_refs: ['urn:example:decision:dec-20261027-0001'],
  human_approver: { principal_id: 'user:payables-operator-07@example.com', oversight_pattern: 'STANDING_BOUNDED_GRANT', grant_id: 'grant-tickets-create-20261027-a' },
  suspension_trigger_state: CLEAR,
  rollback_token: 'rollback-tickets-20261027-0002',
  control_owner: 'Payables Operations Lead: user:payables-lead-03@example.com',
  ...NAMED,
}
const rB = sign(B)

// T: an ST-01 trip under unattended T2 execution. The proposed payment would take the rolling total to 81 percent of
// the ceiling; human_approver names the owner of the standing T2 grant the agent was running under.
const T = {
  ...receiptMembers('2026-10-27T23:41:10Z'),
  decision_id: 'dec-20261027-0003',
  timestamp_utc: '2026-10-27T23:41:09Z',
  ...COMMON,
  autonomy_tier: 'T2_BOUNDED_AUTO_EXECUTE',
  action_type: 'payments.transfer',
  resolved_action_digest: actionDigest('actions/payment-held.json'),
  blast_radius_usd: 14000,
  cumulative_24h_usd: 81000,
  evidence_refs: ['urn:example:invoice:INV-20502'],
  human_approver: { principal_id: 'user:ap-controller-01@example.com', oversight_pattern: 'UNATTENDED_T2', grant_id: 'grant-doa-payments-t2-20261001' },
  suspension_trigger_state: TRIPPED,
  rollback_token: 'idem-payables-20261027-0003',
  control_owner: 'AP Controller: user:ap-controller-01@example.com',
  ...NAMED,
}

const lastNibbleFlipped = (h) => h.slice(0, -1) + (parseInt(h.slice(-1), 16) ^ 1).toString(16)
const approver = (rec, changes) => ({ ...rec, human_approver: { ...rec.human_approver, ...changes } })
const triggers = (rec, state) => ({ ...rec, suspension_trigger_state: state })
const RECEIPTS = new Map([
  ['records/gated-approval.json', rA],
  ['records/standing-approval.json', rB],
  ['records/trip-record.json', sign(T)],
  ['records/gated-approval-rewritten.json', sign(approver(A, { principal_id: 'user:treasury-checker-05@example.com' }))],
  ['records/signature-altered.json', { ...rA, signature: { ...rA.signature, sig: lastNibbleFlipped(rA.signature.sig) } }],
  ['records/field-changed-after-signing.json', { payload: { ...A, blast_radius_usd: 2500 }, signature: rA.signature }],
  ['records/unexpected-signer.json', sign({ ...A, issuer_id: AGENT_KID }, AGENT, AGENT_KID)],
  ['records/missing-decision-id.json', sign(without(A, 'decision_id'))],
  ['records/missing-human-approver.json', sign(without(A, 'human_approver'))],
  ['records/trip-record-no-approver.json', sign({ ...T, human_approver: null })],
  ['records/evidence-refs-not-array.json', sign({ ...A, evidence_refs: 'urn:example:invoice:INV-20431' })],
  ['records/autonomy-tier-outside-enum.json', sign({ ...A, autonomy_tier: 'T1_ACT_AND_NOTIFY' })],
  ['records/oversight-pattern-outside-enum.json', sign(approver(A, { oversight_pattern: 'MAKER_CHECKER' }))],
  ['records/trigger-status-outside-enum.json', sign(triggers(A, { ...CLEAR, status: 'SUSPENDED' }))],
  ['records/tripped-trigger-st-06.json', sign(triggers(T, { ...TRIPPED, tripped_trigger: 'ST-06' }))],
  ['records/triggers-evaluated-st-06.json', sign(triggers(A, { ...CLEAR, triggers_evaluated: [...ALL_TRIGGERS, 'ST-06'] }))],
  ['records/trigger-state-missing-triggers-evaluated.json', sign(triggers(A, without(CLEAR, 'triggers_evaluated')))],
  ['records/blast-radius-negative.json', sign({ ...A, blast_radius_usd: -25000 })],
  ['records/action-digest-no-prefix.json', sign({ ...A, resolved_action_digest: A.resolved_action_digest.slice('sha256:'.length) })],
  ['records/action-digest-uppercase.json', sign({ ...A, resolved_action_digest: `sha256:${A.resolved_action_digest.slice('sha256:'.length).toUpperCase()}` })],
  ['records/schema-version-1-0-0.json', sign({ ...A, schema_version: '1.0.0' })],
  ['records/schema-sha256-mismatch.json', sign({ ...A, schema_sha256: SCHEMA_JCS_SHA256 })],
  ['records/approver-is-agent.json', sign(approver(A, { principal_id: AGENT_ID }))],
  ['records/grant-not-recorded.json', sign(approver(B, { grant_id: 'grant-tickets-create-20261027-b' }))],
  ['records/timestamp-not-utc.json', sign({ ...A, timestamp_utc: '2026-10-28T09:14:05+11:00' })],
  ['records/timestamp-no-offset.json', sign({ ...A, timestamp_utc: '2026-10-27T22:14:05' })],
  ['records/schema-sha256-prefixed.json', sign({ ...A, schema_sha256: `sha256:${SCHEMA_SHA256}` })],
  ['records/release-while-tripped.json', sign(triggers(B, TRIPPED))],
  ['records/tripped-with-trigger-none.json', sign(triggers(T, { ...TRIPPED, tripped_trigger: 'NONE' }))],
  ['records/clear-naming-st-01.json', sign(triggers(A, { ...CLEAR, tripped_trigger: 'ST-01' }))],
])

// Logs read in order, one receipt per line (verify --replay-chain).
const SEQUENCES = new Map([
  ['records/standing-approval-chain.jsonl', ['records/gated-approval.json', 'records/standing-approval.json']],
  ['records/broken-chain.jsonl', ['records/gated-approval-rewritten.json', 'records/standing-approval.json']],
])

// The expected result of each check. signature and key are @veritasacta/verify's (pass, fail, undecidable); the rest
// are run.mjs's own (pass, fail, not_run). Most cases pass every check but one, so each case writes only its changes.
// grant_recorded runs only where the oversight pattern rests on a standing grant, so A's descendants have it not_run.
const PASSING = {
  signature: 'pass', key: 'pass', chain: 'not_run', schema: 'pass', schema_named: 'pass',
  action_digest: 'pass', approver_not_agent: 'pass', grant_recorded: 'not_run',
}
const checks = (changes = {}) => ({ ...PASSING, ...changes })
const GRANTED = { grant_recorded: 'pass' }
const VALID = { verdict: 'ACCEPT', outcome: 'valid' }
const INVALID = { verdict: 'REJECT', outcome: 'invalid' }
const RECEIPT_VALID = { outcome: 'valid', exit: 0, code: null }
const PAY = 'actions/payment.json'
const TICKET = 'actions/ticket.json'
const HELD = 'actions/payment-held.json'
const S = 'A-DoA v1.1.0'
const reading = (verdict, rationale) => ({ verdict, outcome: verdict === 'ACCEPT' ? 'valid' : 'invalid', rationale })

const alone = (id, file, actions, parent, change, decidedBy, expected, verify, basis, note, extra = {}) => ({
  id, kind: extra.kind ?? (expected.verdict === 'ACCEPT' ? 'accept' : 'reject'), decided_by: decidedBy, check: 'alone', file, actions,
  parent, change, expected: { ...expected, format: extra.format ?? 'holds' }, ...(extra.readings ? { readings: extra.readings } : {}),
  ...(extra.enum ? { relies_on_enum: extra.enum } : {}), verify, basis, note,
})
const unsettled = (id, file, actions, parent, change, decidedBy, expectedChecks, readings, basis, note, format = 'holds') =>
  alone(id, file, actions, parent, change, decidedBy, { checks: expectedChecks }, RECEIPT_VALID, basis, note, { kind: 'unsettled', readings, format })

const CASES = [
  // Accepted.
  alone('gated-approval', 'records/gated-approval.json', [PAY], null, null, [], { ...VALID, checks: checks() }, RECEIPT_VALID, `${S}; MI-24 Machine-Readable Decision Record Schema`,
    'A per-action approval (T1_HUMAN_APPROVAL_REQUIRED, PER_ACTION_APPROVAL) of a 25,000 USD payment, with every breaker CLEAR. The schema requires grant_id here too; with no standing grant to name, the record carries its own approval, prefixed per-action:.'),
  {
    id: 'standing-approval-chain', kind: 'accept', decided_by: [], check: 'sequence', file: 'records/standing-approval-chain.jsonl',
    sequence: SEQUENCES.get('records/standing-approval-chain.jsonl'), line: 2, actions: [PAY, TICKET], parent: null, change: null,
    expected: { ...VALID, checks: checks({ chain: 'pass', ...GRANTED }), format: 'holds' }, verify: { ...RECEIPT_VALID, chains: 1, chain_breaks: 0 },
    basis: `${S}; MI-24 Record the Grant as Approval Evidence; Conformance (informative)`,
    note: 'The approval above, then a ticket released under a recorded standing grant (T2_BOUNDED_AUTO_EXECUTE, STANDING_BOUNDED_GRANT), whose previousReceiptHash is the link to the approval: one chain.',
  },
  alone('trip-record', 'records/trip-record.json', [HELD], null, null, [], { ...VALID, checks: checks(GRANTED) }, RECEIPT_VALID, `${S} suspension_trigger_state; MI-24 Trip and Reset Records`,
    'An ST-01 trip under unattended T2 execution: the proposed 14,000 USD payment would take the rolling total to 81,000 against a ceiling of 100,000. status TRIPPED, tripped_trigger ST-01, the five triggers evaluated, and trigger_evidence with the rolling total, the ceiling and the policy version, which Trip and Reset Records asks of ST-01 (the members inside trigger_evidence are these vectors\' own: the schema defines none). human_approver names the owner of the standing T2 grant.'),

  // (a) The Acta receipt.
  alone('signature-altered', 'records/signature-altered.json', [PAY], 'gated-approval', 'The last hex digit of signature.sig changed.', ['receipt'],
    { ...INVALID, checks: checks({ signature: 'fail' }) }, { outcome: 'invalid', exit: 1, code: 'invalid_signature' }, 'MI-24 Tamper-Evidence vs. Non-repudiation',
    'The record is untouched and every other check passes; the signature does not verify under the pinned gate key.'),
  alone('field-changed-after-signing', 'records/field-changed-after-signing.json', [PAY], 'gated-approval', 'blast_radius_usd changed from 25000 to 2500 after signing, the signature kept.', ['receipt'],
    { ...INVALID, checks: checks({ signature: 'fail' }) }, { outcome: 'invalid', exit: 1, code: 'invalid_signature' }, 'MI-24 Tamper-Evidence vs. Non-repudiation',
    'The changed record still conforms to the schema, so every other check passes on it. Only the signature shows that a member changed after signing.'),
  alone('unexpected-signer', 'records/unexpected-signer.json', [PAY], 'gated-approval', 'Signed with the agent\'s own key, which signature.kid and issuer_id name.', ['receipt'],
    { ...INVALID, checks: checks({ signature: 'undecidable', key: 'fail' }) }, { outcome: 'undecidable', exit: 2, code: 'jwks_fetch_failed' }, 'MI-24 Tamper-Evidence vs. Non-repudiation',
    'A signature that verifies under the key it names, the agent\'s. The relying party pinned the gate\'s key, and MI-24 rests non-repudiation on an institutional signing key or the approver\'s identity. Holding only the pinned key set, the verifier cannot check the signature (undecidable, exit 2), and the key check fails because the record names a key the pinned set does not hold.'),
  {
    id: 'broken-chain', kind: 'reject', decided_by: ['receipt'], check: 'sequence', file: 'records/broken-chain.jsonl',
    sequence: SEQUENCES.get('records/broken-chain.jsonl'), line: 2, actions: [PAY, TICKET], parent: 'standing-approval-chain',
    change: 'Line 1 rewritten after line 2 was appended: another approver named, and the record signed again with the gate key.',
    expected: { ...INVALID, checks: checks({ chain: 'fail', ...GRANTED }), format: 'holds' }, verify: { outcome: 'invalid', exit: 1, code: 'chain_break', chains: 1, chain_breaks: 1 },
    basis: 'MI-24 Tamper-Evidence vs. Non-repudiation; Conformance (informative)',
    note: 'Both records verify under the gate key and pass every other check. Line 2 still links to the approval as first written, so the rewrite shows even to a holder of the gate key: the append-only property the Conformance bullet gives the Acta link.',
  },

  // (b) The A-DoA v1.1.0 schema.
  alone('missing-decision-id', 'records/missing-decision-id.json', [PAY], 'gated-approval', 'decision_id removed, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} required`, 'The receipt verifies; the record lacks a member the schema requires.'),
  alone('missing-human-approver', 'records/missing-human-approver.json', [PAY], 'gated-approval', 'human_approver removed, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail', approver_not_agent: 'not_run' }) }, RECEIPT_VALID, `${S} required`, 'A per-action approval that names no approver.'),
  alone('trip-record-no-approver', 'records/trip-record-no-approver.json', [HELD], 'trip-record', 'human_approver set to null, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail', approver_not_agent: 'not_run' }) }, RECEIPT_VALID, `${S} required; MI-24 Trip and Reset Records`,
    'Settled by v1.1.0: human_approver is required on every record, a trip record included, and null is not an object. MI-24 has a breaker trip with no human decision; the schema still asks the record to name one.'),
  alone('evidence-refs-not-array', 'records/evidence-refs-not-array.json', [PAY], 'gated-approval', 'evidence_refs one string instead of an array, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} evidence_refs`, 'The schema types evidence_refs as an array of strings.'),
  alone('autonomy-tier-outside-enum', 'records/autonomy-tier-outside-enum.json', [PAY], 'gated-approval', 'autonomy_tier set to T1_ACT_AND_NOTIFY, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} autonomy_tier enum`,
    'T1 under the name the A-DoA v1.0 specification gives it, Act & Notify. The v1.1.0 enum calls T1 T1_HUMAN_APPROVAL_REQUIRED.', { enum: '/properties/autonomy_tier' }),
  alone('oversight-pattern-outside-enum', 'records/oversight-pattern-outside-enum.json', [PAY], 'gated-approval', 'human_approver.oversight_pattern set to MAKER_CHECKER, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} oversight_pattern enum`,
    'MI-24\'s own name for the pattern, maker-checker or four-eyes. The v1.1.0 enum has PER_ACTION_APPROVAL, STANDING_BOUNDED_GRANT, DUAL_KEY_APPROVAL and UNATTENDED_T2.', { enum: '/properties/human_approver/properties/oversight_pattern' }),
  alone('trigger-status-outside-enum', 'records/trigger-status-outside-enum.json', [PAY], 'gated-approval', 'suspension_trigger_state.status set to SUSPENDED, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} status enum`, 'The schema\'s states are CLEAR, TRIPPED and RESET.', { enum: '/properties/suspension_trigger_state/properties/status' }),
  alone('tripped-trigger-st-06', 'records/tripped-trigger-st-06.json', [HELD], 'trip-record', 'tripped_trigger set to ST-06, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail', ...GRANTED }) }, RECEIPT_VALID, `${S} tripped_trigger enum`,
    'A sixth trigger. The A-DoA v1.0 specification catalogues seven triggers; v1.1.0 and MI-24 have five, ST-01 to ST-05.', { enum: '/properties/suspension_trigger_state/properties/tripped_trigger' }),
  alone('triggers-evaluated-st-06', 'records/triggers-evaluated-st-06.json', [PAY], 'gated-approval', 'ST-06 added to triggers_evaluated, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} triggers_evaluated items enum`, 'Each evaluated trigger must be one of ST-01 to ST-05.', { enum: '/properties/suspension_trigger_state/properties/triggers_evaluated/items' }),
  alone('trigger-state-missing-triggers-evaluated', 'records/trigger-state-missing-triggers-evaluated.json', [PAY], 'gated-approval', 'triggers_evaluated removed from suspension_trigger_state, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} suspension_trigger_state required`, 'The schema requires status and triggers_evaluated.'),
  alone('blast-radius-negative', 'records/blast-radius-negative.json', [PAY], 'gated-approval', 'blast_radius_usd set to -25000, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} blast_radius_usd minimum`, 'The schema sets a minimum of 0.'),
  alone('action-digest-no-prefix', 'records/action-digest-no-prefix.json', [PAY], 'gated-approval', 'resolved_action_digest without its sha256: prefix, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} resolved_action_digest pattern`,
    'The right digest of the action, so (c) passes; the schema\'s pattern requires the prefix.'),
  alone('action-digest-uppercase', 'records/action-digest-uppercase.json', [PAY], 'gated-approval', 'resolved_action_digest in uppercase hex, then signed.', ['schema'],
    { ...INVALID, checks: checks({ schema: 'fail' }) }, RECEIPT_VALID, `${S} resolved_action_digest pattern`,
    'The right digest of the action, so (c) passes; the schema\'s pattern requires lowercase hex.'),
  alone('schema-version-1-0-0', 'records/schema-version-1-0-0.json', [PAY], 'gated-approval', 'schema_version set to 1.0.0, then signed; schema_sha256 still names the 1.1.0 bytes.', ['schema', 'naming'],
    { ...INVALID, checks: checks({ schema: 'fail', schema_named: 'fail' }) }, RECEIPT_VALID, `${S} schema_version const`,
    'The schema accepts only 1.1.0 (const), and (c) refuses a version other than the pinned schema\'s.'),

  // (c) The schema's name and the digests.
  alone('schema-sha256-mismatch', 'records/schema-sha256-mismatch.json', [PAY], 'gated-approval', 'schema_sha256 set to the SHA-256 of the schema in RFC 8785 form instead of its bytes, then signed.', ['naming'],
    { ...INVALID, checks: checks({ schema_named: 'fail' }) }, RECEIPT_VALID, `${S} schema_sha256: "SHA-256 digest of the schema bytes"`,
    'A digest of the same JSON value, but not of the bytes published. The schema accepts any string here, so only (c) sees it.'),
  alone('action-digest-mismatch', 'records/gated-approval.json', ['actions/payment-modified.json'], 'gated-approval', 'The record is unchanged; the action presented for release pays another account.', ['naming'],
    { ...INVALID, checks: checks({ action_digest: 'fail' }) }, RECEIPT_VALID, `${S} resolved_action_digest; MI-24 Bind the Decision to the Resolved Action`,
    'The same receipt as gated-approval, byte for byte. The approval was granted for one version of the action; the action presented has another to_account, so its digest differs and the approval does not move to it.'),

  // (d) Checks taken from MI-24's text, beyond the schema.
  alone('approver-is-agent', 'records/approver-is-agent.json', [PAY], 'gated-approval', 'human_approver.principal_id set to agent_id, then signed.', ['mi24'],
    { ...INVALID, checks: checks({ approver_not_agent: 'fail' }) }, RECEIPT_VALID, 'MI-24 Checkable Decision Records; Named Oversight Pattern',
    'MI-24\'s first example of a record whose fields contradict each other. The record conforms to the schema, which relates no member to another.'),
  alone('grant-not-recorded', 'records/grant-not-recorded.json', [TICKET], 'standing-approval-chain', 'Line 2\'s grant_id changed to one that no recorded standing approval carries, then signed.', ['mi24'],
    { ...INVALID, checks: checks({ grant_recorded: 'fail' }) }, RECEIPT_VALID, 'MI-24 Checkable Decision Records; Record the Grant as Approval Evidence',
    'MI-24\'s second example: a grant_id that resolves to no recorded standing approval. grants.json stands for the institution\'s record of its grants, which the record cannot carry.'),

  // Not settled by the schema or MI-24: no expected verdict, and every listed reading conforms.
  unsettled('timestamp-not-utc', 'records/timestamp-not-utc.json', [PAY], 'gated-approval', 'timestamp_utc written with a +11:00 offset (Sydney): the same instant, then signed.', ['schema'], checks(),
    [reading('ACCEPT', 'The schema types timestamp_utc as a date-time, and a date-time may carry any offset, whether format is read as an annotation or asserted (ajv-formats accepts it).'),
      reading('REJECT', 'The member is named timestamp_utc, the schema\'s description says "ISO 8601 UTC timestamp", and MI-24 names the member too: the same instant written in UTC would be 2026-10-27T22:14:05Z.')],
    `${S} timestamp_utc; MI-24 Machine-Readable Decision Record Schema`, 'Only the description says UTC; nothing the schema asserts does.'),
  unsettled('timestamp-no-offset', 'records/timestamp-no-offset.json', [PAY], 'gated-approval', 'timestamp_utc written with no offset at all, then signed.', ['schema'], checks(),
    [reading('ACCEPT', 'Draft 2020-12 reads format as an annotation unless a validator is set to assert it, and the schema asserts no pattern of its own.'),
      reading('REJECT', 'A validator that asserts format, as ajv with ajv-formats does, refuses a date-time with no offset.')],
    `${S} timestamp_utc format`, 'The one case here whose verdict turns on whether format is asserted.', 'fails'),
  unsettled('schema-sha256-prefixed', 'records/schema-sha256-prefixed.json', [PAY], 'gated-approval', 'schema_sha256 written as sha256: and the hex, then signed.', ['naming'], checks({ schema_named: 'fail' }),
    [reading('REJECT', 'These vectors write schema_sha256 as lowercase hex with no prefix, and run.mjs holds every record to that encoding.'),
      reading('ACCEPT', 'The schema states no encoding for schema_sha256, and this is the right digest, in the convention its own resolved_action_digest pattern uses.')],
    `${S} schema_sha256`, 'The digest is right; only its encoding differs from the one these vectors chose.'),
  unsettled('release-while-tripped', 'records/release-while-tripped.json', [TICKET], 'standing-approval-chain', 'Line 2\'s suspension_trigger_state replaced with the TRIPPED state of trip-record, then signed.', ['mi24'], checks(GRANTED),
    [reading('ACCEPT', 'v1.1.0 has no member for the decision\'s outcome (approved, rejected, modified, released), so nothing in the record says the action was released. trip-record has the same shape and records a breaker holding an action, not releasing one.'),
      reading('REJECT', 'MI-24 Checkable Decision Records calls a release recorded while suspension_trigger_state names a tripped trigger a record whose fields contradict each other.')],
    'MI-24 Checkable Decision Records; MI-24 Minimum Evidence Set', 'MI-24 calls this a contradiction, but the schema has no field that can express a release.'),
  unsettled('tripped-with-trigger-none', 'records/tripped-with-trigger-none.json', [HELD], 'trip-record', 'tripped_trigger set to NONE, status left TRIPPED, then signed.', ['schema'], checks(GRANTED),
    [reading('ACCEPT', 'The schema relates status and tripped_trigger to nothing, so both values are valid on their own.'),
      reading('REJECT', 'A TRIPPED state that names no tripped trigger contradicts itself, and MI-24 Trip and Reset Records has a trip record name the trigger.')],
    `${S} suspension_trigger_state`, 'The schema does not constrain how status and tripped_trigger agree.'),
  unsettled('clear-naming-st-01', 'records/clear-naming-st-01.json', [PAY], 'gated-approval', 'tripped_trigger set to ST-01, status left CLEAR, then signed.', ['schema'], checks(),
    [reading('ACCEPT', 'The schema relates status and tripped_trigger to nothing, so both values are valid on their own.'),
      reading('REJECT', 'A CLEAR state that names a tripped trigger contradicts itself.')],
    `${S} suspension_trigger_state`, 'The mirror image of tripped-with-trigger-none.'),
]

const json = (value) => JSON.stringify(value, null, 2) + '\n'
const files = new Map()
files.set('issuer-jwks.json', json({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: GATE_KID, x: x(GATE), use: 'sig', ...WINDOW }] }))
files.set('grants.json', json({
  about: 'The recorded standing approvals the relying party resolves a grant_id against (MI-24 Record the Grant as Approval Evidence). MI-24 lists what a grant record persists (the grantor, scope and argument constraints, environment, grant and expiry times, any revocation), and neither MI-24 nor the A-DoA schema defines a format for it, so each entry carries only the identifier the check reads.',
  recorded_standing_approvals: [{ grant_id: 'grant-tickets-create-20261027-a' }, { grant_id: 'grant-doa-payments-t2-20261001' }],
}))
for (const [name, value] of Object.entries(ACTIONS)) files.set(name, json(value))
for (const [name, r] of RECEIPTS) files.set(name, json(r))
for (const [name, members] of SEQUENCES) files.set(name, members.map((m) => JSON.stringify(RECEIPTS.get(m)) + '\n').join(''))
files.set('index.json', json({
  suite: 'finos-mi24-decision-record',
  status: 'Test vectors for the A-DoA Decision Record Schema v1.1.0, the decision record of FINOS MI-24, carried as Veritas Acta receipts. Not reviewed or endorsed by FINOS or by the schema\'s author. Written by ScopeBlind, which maintains draft-farley-acta-signed-receipts and @veritasacta/verify, with AI coding agents: the receipt format author\'s own work, not an independent evaluation.',
  mi24: {
    pull_request: 'https://github.com/finos/ai-governance-framework/pull/412',
    head: '490d0fd73e8f47f459698ee8c6e0843e0f9204cc',
    file: 'docs/_mitigations/mi-24_human-in-the-loop-action-approval-gate.md',
    file_sha256: '86e9d959d8a64c033144c9c1d66fb36ab7e83da4350cffacf103d8dd3462d08a',
  },
  schema: {
    file: SCHEMA_FILE,
    title: schemaValue.title,
    id: schemaValue.$id,
    source: 'https://swostipanda.github.io/schemas/adoa-decision-record.schema.json',
    author: 'Swosti Panda',
    doi: '10.5281/zenodo.23275115',
    licence: 'CC BY 4.0',
    included: 'unchanged, byte for byte, as fetched on 28 October 2026 (see schema/ATTRIBUTION.md)',
    bytes: schemaBytes.length,
    version: SCHEMA_VERSION,
    sha256: SCHEMA_SHA256,
  },
  specification: {
    title: 'Agent Delegation-of-Authority (A-DoA) Framework v1.0 (ADOA-2026-v1), Swosti Panda, CC BY 4.0',
    doi: '10.5281/zenodo.23275115',
    file: 'A-DoA-Specification-v1.0.pdf, 298,542 bytes, md5 a7a232a3b7b84819c134442cbb629113',
    note: 'Not vendored. Its Section 3 lists other required fields (record_id, agent_version, action_class, tier_at_time, owner, decision, approvals[], record_hash and more) and seven suspension triggers, and names the tiers T1 Act & Notify and T3 Act Alone with Audit. These vectors follow the published schema v1.1.0, not that list.',
  },
  profile: 'Each record is the signed payload of a draft-farley-acta-signed-receipts receipt (envelope shape, signed over JCS(payload)). The payload carries the receipt\'s own members (type, issuer_id, issued_at, and previousReceiptHash when chained) beside the A-DoA record; the schema does not forbid other members.',
  record_type: TYPE,
  schema_sha256_encoding: 'Lowercase hex, 64 characters, no prefix: these vectors\' choice, since the schema states none.',
  issuer: { kid: GATE_KID, public_key_hex: GATE.publicKeyHex, seed: '00..10', jwks: 'issuer-jwks.json', window: WINDOW },
  other_keys: { [AGENT_KID]: { public_key_hex: AGENT.publicKeyHex, seed: '00..11', note: 'The agent\'s own key. It signs only records/unexpected-signer.json and is in no key set here.' } },
  grants: 'grants.json',
  invocation: {
    alone: 'verify <file> --jwks issuer-jwks.json --mode receipt --json',
    sequence: 'verify --replay-chain <file> --jwks issuer-jwks.json --json',
  },
  check_kinds: {
    receipt: '(a) The Acta receipt: signature, key and chain, decided by @veritasacta/verify 0.11.1 against the pinned gate key.',
    schema: '(b) The A-DoA Decision Record Schema v1.1.0 as published: its assertions. format is an annotation, as draft 2020-12 has it by default; each date-time is reported beside the result, and asserted only in the mutation sweep.',
    naming: '(c) The schema\'s name and the digests: schema_version and schema_sha256 against the pinned schema bytes, and resolved_action_digest as the schema describes it.',
    mi24: '(d) Checks taken from MI-24\'s text, beyond the schema. They are not schema checks.',
  },
  checks: {
    signature: { kind: 'receipt', description: 'The receipt\'s signature, and its signing input (Section 6.6), under the pinned key set: @veritasacta/verify\'s checks.signature and checks.signing_input.' },
    key: { kind: 'receipt', description: 'The receipt names the pinned gate key (issuer_id is signature.kid), the verifier resolved that key from the pinned key set, and the signed issued_at falls inside its window.' },
    chain: { kind: 'receipt', description: 'In a sequence, each record\'s previousReceiptHash is the Section 6.7 link of the record before it (verify --replay-chain). A record checked alone has no predecessor to follow: not_run.' },
    schema: { kind: 'schema', description: 'The payload validates against the vendored schema, format read as an annotation.' },
    schema_named: { kind: 'naming', description: 'schema_version is the pinned schema\'s version, and schema_sha256 is the lowercase hex SHA-256 of the pinned file\'s bytes.' },
    action_digest: { kind: 'naming', description: 'resolved_action_digest names the SHA-256 of the RFC 8785 bytes of the action and arguments supplied with the case. Its form is the schema\'s pattern, so this compares the value alone.' },
    approver_not_agent: { kind: 'mi24', description: 'human_approver.principal_id is not agent_id (MI-24 Checkable Decision Records). not_run when the record names no human approver.' },
    grant_recorded: { kind: 'mi24', description: 'Where oversight_pattern is STANDING_BOUNDED_GRANT or UNATTENDED_T2, human_approver.grant_id names a standing approval in grants.json (MI-24 Checkable Decision Records). not_run otherwise.' },
  },
  scoring: 'An accept or reject case conforms when the verdict and outcome equal expected. An unsettled case is one neither the schema nor MI-24 decides: it carries no expected verdict, and a verifier conforms on it with any verdict its readings list, the convention of the agent-audit-record corpus in agent-evidence-vectors. decided_by names the check kinds whose checks do not pass, or for an unsettled case the kind that would have to settle it. expected.checks are run.mjs\'s own results, expected.format whether each date-time the schema reaches holds, and verify the outcome, exit status and code @veritasacta/verify 0.11.1 reports for the receipt or, in a sequence, for the line named; another verifier is held to the verdict alone. The verdict combines the checks as Section 5.3 of the -04 editor\'s copy does: invalid if any check ran and failed, undecidable if none failed and one could not decide, otherwise valid.',
  counts: Object.fromEntries(['accept', 'reject', 'unsettled'].map((k) => [k, CASES.filter((c) => c.kind === k).length])),
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
// A file this script no longer writes is stale too.
for (const dir of ['records', 'actions']) {
  const full = path.join(DIR, dir)
  for (const name of fs.existsSync(full) ? fs.readdirSync(full) : []) {
    if (files.has(`${dir}/${name}`)) continue
    if (CHECK) { console.error(`not generated: ${dir}/${name}`); stale += 1 } else fs.rmSync(path.join(full, name))
  }
}
if (CHECK) {
  if (stale) process.exit(1)
  console.log(`finos-mi24-decision-record vectors: ${files.size} files current`)
} else {
  console.log(`finos-mi24-decision-record vectors: wrote ${files.size} files to ${DIR}`)
}
