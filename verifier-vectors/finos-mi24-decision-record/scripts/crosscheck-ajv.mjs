#!/usr/bin/env node
// Optional: compare lib.mjs's dependency-free schema check with ajv's JSON Schema 2020-12 validator, on every record
// payload here and on variants of one payload that reach the keywords no case refuses on.
//
//   npm install --prefix <dir> --no-save --no-audit --no-fund ajv@8.20.0
//   node verifier-vectors/finos-mi24-decision-record/scripts/crosscheck-ajv.mjs <dir>
//
// @veritasacta/verify 0.11.1 depends on exactly ajv 8.20.0, so the prefix it is installed into also serves.
// Exit: 0 the two agree on every payload, 1 they disagree, 2 usage or ajv not found.

import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { checkSchema, validate } from '../lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
if (!process.argv[2]) { console.error('usage: crosscheck-ajv.mjs <directory whose node_modules holds ajv>'); process.exit(2) }
let Ajv2020
let ajvVersion
try {
  const require = createRequire(path.join(path.resolve(process.argv[2]), 'node_modules', 'index.js'))
  Ajv2020 = require('ajv/dist/2020').default
  ajvVersion = require('ajv/package.json').version
} catch (e) {
  console.error(`ajv not found under ${process.argv[2]}: ${e.message.split('\n')[0]}`)
  process.exit(2)
}

const index = JSON.parse(fs.readFileSync(path.join(DIR, 'index.json'), 'utf8'))
const schema = JSON.parse(fs.readFileSync(path.join(DIR, index.schema.file), 'utf8'))
checkSchema(schema)
// Strict mode, less its strictRequired lint, which flags a required-only anyOf branch: an ajv style rule, not a
// draft 2020-12 one. Union types are what the draft writes for grant_id and suspension_trigger_state.
const ajvCheck = new Ajv2020({ strict: true, strictRequired: false, allowUnionTypes: true, allErrors: true }).compile(schema)

const payloads = []
for (const name of fs.readdirSync(path.join(DIR, 'records')).sort()) {
  const text = fs.readFileSync(path.join(DIR, 'records', name), 'utf8')
  const lines = name.endsWith('.jsonl') ? text.split('\n').filter((l) => l.trim()) : [text]
  lines.forEach((l, i) => payloads.push([`records/${name}${lines.length > 1 ? ` line ${i + 1}` : ''}`, JSON.parse(l).payload]))
}
const base = JSON.parse(fs.readFileSync(path.join(DIR, 'records', 'gated-approval.json'), 'utf8')).payload
const variant = (label, change) => { const p = structuredClone(base); change(p); payloads.push([`variant: ${label}`, p]) }
variant('decision_id empty', (p) => { p.decision_id = '' })
variant('suspension_trigger_state an empty object', (p) => { p.suspension_trigger_state = {} })
variant('suspension_trigger_state an object', (p) => { p.suspension_trigger_state = { trigger: 'ST-01' } })
variant('suspension_trigger_state a number', (p) => { p.suspension_trigger_state = 1 })
variant('neither idempotency_key nor rollback_token', (p) => { delete p.idempotency_key })
variant('rollback_token instead of idempotency_key', (p) => { delete p.idempotency_key; p.rollback_token = 'r' })
variant('evidence_refs empty', (p) => { p.evidence_refs = [] })
variant('evidence_refs holding an empty string', (p) => { p.evidence_refs = [''] })
variant('evidence_refs holding a number', (p) => { p.evidence_refs = [1] })
variant('grant_id empty', (p) => { p.human_approver.grant_id = '' })
variant('grant_id absent', (p) => { delete p.human_approver.grant_id })
variant('blast_radius_usd a string', (p) => { p.blast_radius_usd = '25000' })
variant('blast_radius_usd negative', (p) => { p.blast_radius_usd = -1 })
variant('resolved_action_digest in uppercase hex', (p) => { p.resolved_action_digest = p.resolved_action_digest.toUpperCase() })
variant('timestamp_utc with +00:00', (p) => { p.timestamp_utc = '2026-10-27T22:14:05+00:00' })
variant('timestamp_utc with no offset', (p) => { p.timestamp_utc = '2026-10-27T22:14:05' })
variant('timestamp_utc with fractional seconds', (p) => { p.timestamp_utc = '2026-10-27T22:14:05.250Z' })
variant('timestamp_utc with Arabic-Indic digits', (p) => { p.timestamp_utc = '\u0662\u0660\u0662\u0666-10-27T22:14:05Z' })
variant('an extra member', (p) => { p.x_extra = true })
variant('the payload an array', () => {})
payloads[payloads.length - 1][1] = [base]

let disagree = 0
for (const [label, payload] of payloads) {
  const ours = validate(schema, payload).length === 0
  const theirs = ajvCheck(payload)
  if (ours !== theirs) { disagree += 1; console.log(`  DISAGREE  ${label}: lib.mjs ${ours ? 'valid' : 'invalid'}, ajv ${theirs ? 'valid' : 'invalid'}`) }
  else console.log(`  agree     ${label}: ${ours ? 'valid' : 'invalid'}`)
}
console.log(`\najv ${ajvVersion} (draft 2020-12, strict but for strictRequired): ${payloads.length - disagree} of ${payloads.length} payloads agree`)
process.exit(disagree ? 1 : 0)
