#!/usr/bin/env node
// A versioned follow-up. The v1.1.0 records and verdicts remain reproducible in the parent directory.
// Adapt their payloads explicitly, sign again with the public fixture seeds, and add hand-written expectations.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { keyPairFromSeed, sha256Hex, signHex } from '../../../../evidence-predicate/lib.mjs'
import { checkSchema } from '../../lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const OLD = path.dirname(DIR)
const CHECK = process.argv.includes('--check')
const read = (file) => fs.readFileSync(path.join(OLD, file))
const json = (value) => JSON.stringify(value, null, 2) + '\n'
const original = JSON.parse(read('index.json'))
const SCHEMA_FILE = 'schema/adoa-decision-record.schema.json'
const HASH = '5713e4286dc8b99d49c012db28c6534853a43d16c33bdf08521050a2f0e3821e'
const bytes = fs.readFileSync(path.join(DIR, SCHEMA_FILE))
if (crypto.createHash('sha256').update(bytes).digest('hex') !== HASH) throw new Error('v1.2.0 schema differs from the author-announced bytes')
const schema = JSON.parse(bytes)
checkSchema(schema)
if (schema.properties.schema_version.const !== '1.2.0' || schema.$id.includes('#')) throw new Error('wrong schema version or fragmented $id')
// These public deterministic test seeds are the same as the historical suite, never production keys.
const gate = keyPairFromSeed('0'.repeat(62) + '10')
const agent = keyPairFromSeed('0'.repeat(62) + '11')
const sign = (payload, key = gate, kid = original.issuer.kid) => ({ payload, signature: { alg: 'EdDSA', kid, sig: signHex(payload, key.privateKey) } })
const flip = (hex) => hex.slice(0, -1) + (parseInt(hex.slice(-1), 16) ^ 1).toString(16)
const tripFiles = new Set(['trip-record', 'trip-record-no-approver', 'tripped-trigger-st-06', 'tripped-with-trigger-none'].map((id) => `records/${id}.json`))
const records = new Map()
for (const name of fs.readdirSync(path.join(OLD, 'records')).filter((name) => name.endsWith('.json'))) {
  const file = `records/${name}`
  const p = JSON.parse(read(file)).payload
  if (p.schema_version === '1.1.0') p.schema_version = '1.2.0'
  p.schema_sha256 = name === 'schema-sha256-mismatch.json' ? sha256Hex(schema) : name === 'schema-sha256-prefixed.json' ? `sha256:${HASH}` : HASH
  p.decision_outcome = tripFiles.has(file) ? 'CIRCUIT_BREAKER_TRIP' : 'APPROVED'
  records.set(file, sign(p))
}
const A = records.get('records/gated-approval.json').payload
const T = records.get('records/trip-record.json').payload
// Every adapted successor links to the newly signed v1.2.0 predecessor.
for (const [file, receipt] of records) {
  if (receipt.payload.previousReceiptHash) records.set(file, sign({ ...receipt.payload, previousReceiptHash: `sha256:${sha256Hex(sign(A))}` }))
}
records.set('records/signature-altered.json', { ...sign(A), signature: { ...sign(A).signature, sig: flip(sign(A).signature.sig) } })
records.set('records/field-changed-after-signing.json', { payload: { ...A, blast_radius_usd: 2500 }, signature: sign(A).signature })
const agentKid = 'test:mi24-agent:ed25519'
records.set('records/unexpected-signer.json', sign({ ...A, issuer_id: agentKid }, agent, agentKid))

const cases = structuredClone(original.cases)
for (const c of cases) {
  c.basis = c.basis.replaceAll('v1.1.0', 'v1.2.0')
  c.adapted_from = `../index.json#${c.id}`
  c.note = `Adapted from the historical v1.1.0 case ${c.id}; schema version/digest and decision_outcome are updated and receipts re-signed. ${c.change ?? 'Same scenario.'}`
  c.expected.checks.release_not_tripped = tripFiles.has(c.file) ? 'not_run' : 'pass'
}
const byId = (id) => cases.find((c) => c.id === id)
const settle = (id, checks, note) => {
  const c = byId(id)
  c.kind = 'reject'
  delete c.readings
  Object.assign(c.expected, { verdict: 'REJECT', outcome: 'invalid' })
  Object.assign(c.expected.checks, checks)
  c.note = note
}
settle('timestamp-not-utc', { schema: 'fail' }, 'v1.2.0 rejects the non-UTC offset by pattern, even with format treated as an annotation.')
settle('timestamp-no-offset', { schema: 'fail' }, 'v1.2.0 rejects a missing UTC suffix by pattern and by asserted date-time format.')
settle('schema-sha256-prefixed', { schema: 'fail' }, 'v1.2.0 requires bare lowercase hex; schema_named also rejects the prefix.')
byId('schema-sha256-prefixed').decided_by = ['schema', 'naming']
settle('release-while-tripped', { release_not_tripped: 'fail' }, 'APPROVED makes release explicit. MI-24 Checkable Decision Records rejects it when status is TRIPPED; the JSON Schema alone accepts it.')
byId('release-while-tripped').basis = 'MI-24 Checkable Decision Records; v1.2.0 decision_outcome'
// The remaining status/trigger cross-field questions are not newly constrained by v1.2.0.
for (const id of ['tripped-with-trigger-none', 'clear-naming-st-01']) {
  byId(id).readings = byId(id).readings.map((r) => ({ ...r, rationale: r.rationale.replaceAll('v1.1.0', 'v1.2.0') }))
}

const pass = { ...byId('gated-approval').expected.checks }
const receiptValid = { outcome: 'valid', exit: 0, code: null }
const PAY = 'actions/payment.json'
function add(id, payload, expectedChecks, note, extra = {}) {
  const file = `records/${id}.json`
  records.set(file, sign(payload))
  const checks = { ...pass, ...expectedChecks }
  const invalid = Object.values(checks).includes('fail')
  cases.push({
    id, kind: invalid ? 'reject' : 'accept', decided_by: invalid ? [...new Set(Object.keys(checks).filter((k) => checks[k] === 'fail').map((k) => k === 'schema' ? 'schema' : k === 'release_not_tripped' ? 'mi24' : 'naming'))] : [],
    check: 'alone', file, actions: [PAY], parent: 'gated-approval', change: note,
    expected: { verdict: invalid ? 'REJECT' : 'ACCEPT', outcome: invalid ? 'invalid' : 'valid', checks, format: 'holds' },
    verify: receiptValid, basis: 'A-DoA v1.2.0; MI-24 Checkable Decision Records', note, ...extra,
  })
}
const without = (p, member) => Object.fromEntries(Object.entries(p).filter(([key]) => key !== member))
add('missing-decision-outcome', without(A, 'decision_outcome'), { schema: 'fail', release_not_tripped: 'not_run' }, 'decision_outcome is required.')
add('decision-outcome-outside-enum', { ...A, decision_outcome: 'RELEASED' }, { schema: 'fail', release_not_tripped: 'not_run' }, 'An unlisted outcome is rejected.', { relies_on_enum: '/properties/decision_outcome' })
add('decision-outcome-wrong-type', { ...A, decision_outcome: false }, { schema: 'fail', release_not_tripped: 'not_run' }, 'decision_outcome must be a string.')
const modifiedAction = JSON.parse(read('actions/payment-modified.json'))
const M = { ...A, decision_id: 'dec-20261027-0004', human_approver: { ...A.human_approver, grant_id: 'per-action:dec-20261027-0004' }, decision_outcome: 'APPROVED_WITH_MODIFICATION', modification_ref: A.decision_id, resolved_action_digest: `sha256:${sha256Hex(modifiedAction)}` }
add('approved-with-modification', M, {}, 'A modified approval links its prior decision and binds the changed action.', { actions: ['actions/payment-modified.json'] })
add('modification-ref-wrong-type', { ...M, modification_ref: 42 }, { schema: 'fail' }, 'Optional modification_ref must be a string when present.', { actions: ['actions/payment-modified.json'] })
add('modified-release-while-tripped', { ...M, suspension_trigger_state: T.suspension_trigger_state }, { release_not_tripped: 'fail' }, 'An approval with modification is also a release and cannot carry status TRIPPED.', { actions: ['actions/payment-modified.json'] })
add('modification-ref-absent', without(M, 'modification_ref'), {}, 'The schema does not require modification_ref conditionally; MI-24 asks for modification linkage. No linkage resolver is claimed here.', { actions: ['actions/payment-modified.json'] })
const absent = byId('modification-ref-absent')
absent.kind = 'unsettled'
absent.decided_by = ['mi24']
delete absent.expected.verdict
delete absent.expected.outcome
absent.readings = [
  { verdict: 'ACCEPT', outcome: 'valid', rationale: 'The schema makes modification_ref optional and no supplied linkage resolver establishes a contradiction.' },
  { verdict: 'REJECT', outcome: 'invalid', rationale: 'MI-24 Minimum Evidence Set asks for modification linkage, which this record does not supply.' },
]
for (const outcome of ['DENIED', 'ESCALATED_T1', 'HOLD_PENDING_RECONCILIATION', 'CIRCUIT_BREAKER_RESET']) {
  const reset = outcome === 'CIRCUIT_BREAKER_RESET'
  add(outcome.toLowerCase().replaceAll('_', '-'), { ...A, decision_outcome: outcome, suspension_trigger_state: reset ? { ...T.suspension_trigger_state, status: 'RESET' } : T.suspension_trigger_state }, { release_not_tripped: 'not_run' }, `${outcome} is not a release. ${reset ? 'This checks the reset record shape, not live reconciliation or grant renewal.' : 'The outcome may be recorded while the breaker is tripped.'}`)
}
add('timestamp-plus-zero', { ...A, timestamp_utc: '2026-10-27T22:14:05+00:00' }, {}, 'Explicit +00:00 UTC is accepted.')
add('timestamp-fractional-utc', { ...A, timestamp_utc: '2026-10-27T22:14:05.123Z' }, {}, 'Fractional seconds with Z are accepted.')
for (const [id, value] of [['minus-zero', '2026-10-27T22:14:05-00:00'], ['lowercase', '2026-10-27t22:14:05z']]) {
  add(`timestamp-${id}`, { ...A, timestamp_utc: value }, { schema: 'fail' }, 'The strict UTC pattern accepts uppercase T and Z or +00:00 only.')
}
add('timestamp-invalid-date', { ...A, timestamp_utc: '2026-02-30T22:14:05Z' }, { schema: 'fail' }, 'The UTC pattern alone accepts this impossible calendar date; asserted date-time format must reject it.', { relies_on_format: true })
byId('timestamp-invalid-date').expected.format = 'fails'
add('schema-sha256-uppercase', { ...A, schema_sha256: HASH.toUpperCase() }, { schema: 'fail', schema_named: 'fail' }, 'schema_sha256 must use lowercase hex.')
add('schema-sha256-short', { ...A, schema_sha256: HASH.slice(1) }, { schema: 'fail', schema_named: 'fail' }, 'schema_sha256 must contain exactly 64 hex characters.')
add('schema-version-1-1-0', { ...A, schema_version: '1.1.0' }, { schema: 'fail', schema_named: 'fail' }, 'The v1.2.0 schema rejects the historical version constant.')

const files = new Map()
for (const file of ['issuer-jwks.json', 'grants.json', ...fs.readdirSync(path.join(OLD, 'actions')).map((name) => `actions/${name}`)]) files.set(file, read(file).toString('utf8'))
for (const [file, receipt] of records) files.set(file, json(receipt))
for (const c of cases.filter((c) => c.check === 'sequence')) files.set(c.file, c.sequence.map((file) => JSON.stringify(records.get(file)) + '\n').join(''))
const index = {
  ...original,
  suite: 'finos-mi24-decision-record/v1.2.0',
  status: 'ScopeBlind follow-up for A-DoA v1.2.0, authored with Codex. Not reviewed or endorsed by FINOS or the schema author. The author endorsed only the historical 31-case v1.1.0 suite; that review does not extend to these adapted or new cases.',
  historical_review: { cases: 31, schema_version: '1.1.0', commit: '9e334fbb6a60c18403b0f411d0fd92e275ede58a', url: 'https://github.com/finos/ai-governance-framework/pull/412#issuecomment-6553545848' },
  mi24: { ...original.mi24, head: 'e668312fe060da311d27373a4ff5e3e04a43b4b7', file_sha256: '8196156ce361bcbc07d6e98b7d9a67fa5dd07caa3d6ac1bfb0d1cdbc267d47ac' },
  schema: { ...original.schema, title: schema.title, id: schema.$id, version: '1.2.0', bytes: bytes.length, sha256: HASH, included: 'unchanged, byte for byte, fetched 3 November 2026 and verified against the author-announced SHA-256 (see schema/ATTRIBUTION.md)' },
  schema_format: 'assert',
  schema_sha256_encoding: 'Bare lowercase hex, exactly 64 characters, as required by v1.2.0.',
  check_kinds: { ...original.check_kinds, schema: '(b) A-DoA v1.2.0 assertions, including date-time format asserted by this profile. AJV 2020-12 and ajv-formats independently cross-check every payload with meta-schema validation enabled.' },
  checks: { ...original.checks, schema: { kind: 'schema', description: 'The payload validates against the unchanged v1.2.0 schema with date-time format asserted.' }, release_not_tripped: { kind: 'mi24', description: 'APPROVED and APPROVED_WITH_MODIFICATION cannot carry suspension_trigger_state.status TRIPPED. Other outcomes: not_run. This does not evaluate a live gate.', source: 'https://github.com/finos/ai-governance-framework/blob/e668312fe060da311d27373a4ff5e3e04a43b4b7/docs/_mitigations/mi-24_human-in-the-loop-action-approval-gate.md#6-recording-the-approval-evidence'  } },
  counts: Object.fromEntries(['accept', 'reject', 'unsettled'].map((kind) => [kind, cases.filter((c) => c.kind === kind).length])),
  cases,
}
index.specification.note = 'Historical companion PDF provenance only; this versioned suite follows the pinned published schema v1.2.0 and MI-24 text above.'
files.set('index.json', json(index))
let stale = 0
for (const [file, text] of files) {
  const target = path.join(DIR, file)
  if (CHECK) {
    if (!fs.existsSync(target) || fs.readFileSync(target, 'utf8') !== text) { console.error(`stale: ${file}`); stale++ }
  } else { fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, text) }
}
for (const folder of ['records', 'actions']) {
  for (const name of fs.existsSync(path.join(DIR, folder)) ? fs.readdirSync(path.join(DIR, folder)) : []) {
    if (!files.has(`${folder}/${name}`)) { console.error(`not generated: ${folder}/${name}`); stale++ }
  }
}
if (stale) process.exit(1)
console.log(`finos-mi24-decision-record/v1.2.0: ${files.size} files ${CHECK ? 'current' : 'written'}; ${cases.length} cases`)
