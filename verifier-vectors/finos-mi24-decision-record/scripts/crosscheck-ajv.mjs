#!/usr/bin/env node
// Optional: compare lib.mjs's dependency-free schema check with ajv's JSON Schema 2020-12 validator on the vendored
// A-DoA v1.1.0 schema, on every record payload here and on variants of one payload that reach the rest of the schema.
//
//   npm install --prefix <dir> --no-save --no-audit --no-fund ajv@8.20.0 ajv-formats@3.0.1
//   node verifier-vectors/finos-mi24-decision-record/scripts/crosscheck-ajv.mjs <dir>
//
// @veritasacta/verify 0.11.1 depends on exactly these two versions, so the prefix it is installed into also serves.
// Three comparisons:
//   1. format as an annotation (the 2020-12 default): lib.mjs and ajv must agree on every payload.
//   2. format asserted: lib.mjs's RFC 3339 date-time against ajv-formats. They must agree on every payload but the two
//      variants listed in KNOWN, where ajv-formats accepts what RFC 3339's grammar does not.
//   3. the payloads whose verdict changes when format is asserted, as ajv reports them.
// ajv refuses to compile the schema as published, because its $id carries a fragment, so the comparisons compile it
// unchanged with meta-schema validation off. Exit: 0 as above, 1 otherwise, 2 usage or ajv not found.

import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { checkSchema, validate } from '../lib.mjs'

const DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
if (!process.argv[2]) { console.error('usage: crosscheck-ajv.mjs <directory whose node_modules holds ajv and ajv-formats>'); process.exit(2) }
let Ajv2020, addFormats, versions
try {
  const require = createRequire(path.join(path.resolve(process.argv[2]), 'node_modules', 'index.js'))
  Ajv2020 = require('ajv/dist/2020').default
  addFormats = require('ajv-formats').default
  versions = `ajv ${require('ajv/package.json').version}, ajv-formats ${require('ajv-formats/package.json').version}`
} catch (e) {
  console.error(`ajv or ajv-formats not found under ${process.argv[2]}: ${e.message.split('\n')[0]}`)
  process.exit(2)
}

const index = JSON.parse(fs.readFileSync(path.join(DIR, 'index.json'), 'utf8'))
const schema = JSON.parse(fs.readFileSync(path.join(DIR, index.schema.file), 'utf8'))
checkSchema(schema)
// Strict mode, less its strictRequired lint (an ajv style rule, not a 2020-12 one).
const STRICT = { strict: true, strictRequired: false, allErrors: true }
let refusal = 'none: ajv compiled it'
try { new Ajv2020(STRICT).compile(schema) } catch (e) { refusal = e.message.split('\n')[0] }
const annotated = new Ajv2020({ ...STRICT, validateSchema: false, validateFormats: false }).compile(schema)
const assertingAjv = new Ajv2020({ ...STRICT, validateSchema: false })
addFormats(assertingAjv)
const asserted = assertingAjv.compile(schema)

const payloads = []
for (const name of fs.readdirSync(path.join(DIR, 'records')).sort()) {
  const text = fs.readFileSync(path.join(DIR, 'records', name), 'utf8')
  const lines = name.endsWith('.jsonl') ? text.split('\n').filter((l) => l.trim()) : [text]
  lines.forEach((l, i) => payloads.push([`records/${name}${lines.length > 1 ? ` line ${i + 1}` : ''}`, JSON.parse(l).payload]))
}
const base = JSON.parse(fs.readFileSync(path.join(DIR, 'records', 'gated-approval.json'), 'utf8')).payload
const variant = (label, change) => { const p = structuredClone(base); const r = change(p); payloads.push([`variant: ${label}`, r === undefined ? p : r]) }
const at = (p, value) => { p.timestamp_utc = value }
variant('decision_id empty', (p) => { p.decision_id = '' })
variant('autonomy_tier T0_OBSERVE', (p) => { p.autonomy_tier = 'T0_OBSERVE' })
variant('autonomy_tier T3_PROHIBITED', (p) => { p.autonomy_tier = 'T3_PROHIBITED' })
variant('autonomy_tier in lowercase', (p) => { p.autonomy_tier = p.autonomy_tier.toLowerCase() })
variant('oversight_pattern DUAL_KEY_APPROVAL', (p) => { p.human_approver.oversight_pattern = 'DUAL_KEY_APPROVAL' })
variant('oversight_pattern UNATTENDED_T2', (p) => { p.human_approver.oversight_pattern = 'UNATTENDED_T2' })
variant('blast_radius_usd 0', (p) => { p.blast_radius_usd = 0 })
variant('blast_radius_usd -0.01', (p) => { p.blast_radius_usd = -0.01 })
variant('blast_radius_usd a string', (p) => { p.blast_radius_usd = '25000' })
variant('cumulative_24h_usd -1', (p) => { p.cumulative_24h_usd = -1 })
variant('evidence_refs empty', (p) => { p.evidence_refs = [] })
variant('evidence_refs holding a number', (p) => { p.evidence_refs = [1] })
variant('human_approver with no grant_id', (p) => { delete p.human_approver.grant_id })
variant('grant_id empty', (p) => { p.human_approver.grant_id = '' })
variant('human_approver with an extra member', (p) => { p.human_approver.second_principal_id = 'user:x@example.com' })
variant('suspension_trigger_state with no status', (p) => { delete p.suspension_trigger_state.status })
variant('suspension_trigger_state with no tripped_trigger', (p) => { delete p.suspension_trigger_state.tripped_trigger })
variant('trigger_evidence an array', (p) => { p.suspension_trigger_state.trigger_evidence = [] })
variant('triggers_evaluated empty', (p) => { p.suspension_trigger_state.triggers_evaluated = [] })
variant('status RESET', (p) => { p.suspension_trigger_state.status = 'RESET' })
variant('rollback_token absent', (p) => { delete p.rollback_token })
variant('control_owner absent', (p) => { delete p.control_owner })
variant('control_owner a number', (p) => { p.control_owner = 1 })
variant('schema_version 1.1', (p) => { p.schema_version = '1.1' })
variant('schema_sha256 not a digest', (p) => { p.schema_sha256 = 'not a digest' })
variant('schema_sha256 absent', (p) => { delete p.schema_sha256 })
variant('resolved_action_digest under sha512:', (p) => { p.resolved_action_digest = `sha512:${'0'.repeat(128)}` })
variant('timestamp_utc at +11:00', (p) => at(p, '2026-10-28T09:14:05+11:00'))
variant('timestamp_utc with no offset', (p) => at(p, '2026-10-27T22:14:05'))
variant('timestamp_utc with a lowercase t and z', (p) => at(p, '2026-10-27t22:14:05z'))
variant('timestamp_utc with a space for T', (p) => at(p, '2026-10-27 22:14:05Z'))
variant('timestamp_utc offset with no colon', (p) => at(p, '2026-10-28T09:14:05+1100'))
variant('timestamp_utc on 30 February', (p) => at(p, '2026-02-30T22:14:05Z'))
variant('timestamp_utc on a leap second', (p) => at(p, '2026-12-31T23:59:60Z'))
variant('timestamp_utc in Arabic-Indic digits', (p) => at(p, '\u0662\u0660\u0662\u0666-10-27T22:14:05Z'))
variant('timestamp_utc not a date', (p) => at(p, 'yesterday'))
variant('an extra member', (p) => { p.x_extra = true })
variant('the payload an array', () => [base])
variant('the payload null', () => null)
// Where ajv-formats accepts what RFC 3339 section 5.6 does not; lib.mjs follows the RFC.
const KNOWN = new Set(['variant: timestamp_utc with a space for T', 'variant: timestamp_utc offset with no colon'])

let failures = 0
const differ = []
const known = []
for (const [label, payload] of payloads) {
  const ours = validate(schema, payload).errors.length === 0
  const oursAsserted = validate(schema, payload, { assertFormat: true }).errors.length === 0
  const theirs = annotated(payload)
  const theirsAsserted = asserted(payload)
  const word = (v) => (v ? 'valid' : 'invalid')
  if (ours !== theirs) { failures += 1; console.log(`  DISAGREE  ${label}, format an annotation: lib.mjs ${word(ours)}, ajv ${word(theirs)}`) }
  if (oursAsserted !== theirsAsserted) {
    if (KNOWN.has(label)) known.push(`${label}: lib.mjs ${word(oursAsserted)}, ajv-formats ${word(theirsAsserted)}`)
    else { failures += 1; console.log(`  DISAGREE  ${label}, format asserted: lib.mjs ${word(oursAsserted)}, ajv-formats ${word(theirsAsserted)}`) }
  } else if (KNOWN.has(label)) { failures += 1; console.log(`  EXPECTED A DIFFERENCE  ${label}: both ${word(theirsAsserted)}`) }
  if (theirs !== theirsAsserted) differ.push(`${label}: ${word(theirs)} with format an annotation, ${word(theirsAsserted)} asserted`)
  console.log(`  ${ours === theirs ? 'agree' : 'DIFFER'}  ${label}: ${word(theirs)}${theirs !== theirsAsserted ? `, ${word(theirsAsserted)} with format asserted` : ''}`)
}
console.log(`\n${versions}, draft 2020-12, strict but for strictRequired`)
console.log(`the schema as published, meta-schema checked: ${refusal}`)
console.log(`compiled unchanged with meta-schema validation off: ${payloads.length} payloads`)
console.log(`format an annotation: lib.mjs and ajv agree on ${payloads.length - payloads.filter(([l, p]) => (validate(schema, p).errors.length === 0) !== annotated(p)).length} of ${payloads.length}`)
console.log(`format asserted: lib.mjs and ajv-formats differ only where RFC 3339 and ajv-formats do (${known.length}):${known.map((k) => `\n  ${k}`).join('')}`)
console.log(`verdicts that change when ajv asserts format (${differ.length}):${differ.map((d) => `\n  ${d}`).join('')}`)
process.exit(failures ? 1 : 0)
