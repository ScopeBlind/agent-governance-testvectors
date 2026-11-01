#!/usr/bin/env node
// Test vectors for the A-DoA Decision Record Schema v1.1.0 (Swosti Panda, CC BY 4.0), the decision record of FINOS
// MI-24, on records carried as the signed payload of Veritas Acta receipts (draft-farley-acta-signed-receipts). Not
// reviewed or endorsed by FINOS or by the schema's author. See README.md.
//
//   node verifier-vectors/finos-mi24-decision-record/run.mjs
//
//   VERIFY_PKG  the verifier run through npx (default: @veritasacta/verify@0.11.1, published with npm provenance)
//   VERIFY_CMD  instead of npx, a command prefix, e.g. the verify bin of `npm install --prefix <dir> @veritasacta/verify@0.11.1`
//
// Four kinds of check, in order:
//   (a) receipt  the pinned verifier checks each receipt's signature, key and chain against the pinned gate key
//   (b) schema   lib.mjs validates the payload against the vendored schema; format is an annotation, reported apart
//   (c) naming   schema_version and schema_sha256 against the pinned schema bytes, and resolved_action_digest
//   (d) mi24     checks taken from MI-24's text, beyond the schema: the approver is not the agent, a grant is recorded
// Then a mutation sweep turns each check off, computes each digest over the wrong bytes, asserts format, and drops each
// enum from an in-memory copy of the schema, and requires that exactly the cases resting on each stop matching, so a
// pass cannot come from a check that never fires.
//
// Exit: 0 every case matched and every mutation was caught, 1 otherwise, 77 the pinned verifier cannot run here.

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { actionDigest, approverNotAgent, checkSchema, grantRecorded, schemaNamed, validate } from './lib.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const PKG = process.env.VERIFY_PKG || '@veritasacta/verify@0.11.1'
const CMD = process.env.VERIFY_CMD ? process.env.VERIFY_CMD.split(' ').filter(Boolean) : ['npx', '--yes', PKG]

const read = (name) => fs.readFileSync(path.join(HERE, name))
const readJson = (name) => JSON.parse(read(name).toString('utf8'))
const index = readJson('index.json')
const schemaBytes = read(index.schema.file)
const SCHEMA_VALUE = JSON.parse(schemaBytes.toString('utf8'))
checkSchema(SCHEMA_VALUE)
const PINNED = { version: index.schema.version, bytes: schemaBytes }
const grants = new Set(readJson(index.grants).recorded_standing_approvals.map((g) => g.grant_id))
const CHECKS = Object.keys(index.checks)
const KIND_OF = Object.fromEntries(Object.entries(index.checks).map(([name, c]) => [name, c.kind]))

function verify(args) {
  const p = spawnSync(CMD[0], [...CMD.slice(1), ...args], { cwd: HERE, encoding: 'utf8' })
  let out = null
  try { out = JSON.parse(p.stdout) } catch { /* reported by the caller */ }
  return { rc: p.status, out }
}

const probe = spawnSync(CMD[0], [...CMD.slice(1), '--version'], { encoding: 'utf8' })
if (probe.status !== 0) {
  const why = (probe.stderr || '').split('\n').find((l) => l.trim()) || `exit ${probe.status}`
  console.log(`skip: ${CMD.join(' ')} cannot run here (${why.trim()})`)
  process.exit(77)
}
console.log(`verifier: ${process.env.VERIFY_CMD || PKG} (${probe.stdout.trim()})`)
console.log(`schema: ${index.schema.title}, ${index.schema.bytes} bytes, sha256 ${index.schema.sha256}`)

let passed = 0
let failed = 0
const ok = (msg) => { passed += 1; console.log(`  ok    ${msg}`) }
const bad = (msg) => { failed += 1; console.log(`  FAIL  ${msg}`) }

const gen = spawnSync(process.execPath, [path.join(HERE, 'scripts', 'generate.mjs'), '--check'], { encoding: 'utf8' })
if (gen.status !== 0) bad(`the vectors are stale: ${(gen.stderr || gen.stdout).trim()}`)

// A check's results over several records, or several results within one: the worst decides.
const RANK = { not_run: 0, pass: 1, undecidable: 2, fail: 3 }
const worst = (results) => results.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'not_run')
// A verifier result other than pass or fail (absent, or a value this runner does not know) decides nothing.
const decides = (result) => (result === 'pass' || result === 'fail' ? result : 'undecidable')

// (a) What the verifier reported for one receipt, as the two checks it decides.
function receiptChecks(entry) {
  const c = (entry && entry.checks) || {}
  const signature = worst([decides(c.signing_input?.result), decides(c.signature?.result)])
  const key = entry && entry.kid === index.issuer.kid && c.issuer_kid?.result === 'pass' && entry.keyStatus?.result === 'inside'
  return { signature, key: key ? 'pass' : 'fail' }
}

const recordsOf = (c) => (c.check === 'sequence'
  ? read(c.file).toString('utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l))
  : [readJson(c.file)])

// mutation: null for the real run, or one of { disable: <check> } (the check reports pass wherever it runs),
// { schemaDigest: 'jcs' } and { actionDigest: 'file-bytes' } (a digest over the wrong bytes), { assertFormat: true },
// and { schema: <a changed copy> } (validate against it instead).
function evaluate(c, v, mutation = null) {
  const schema = mutation?.schema ?? SCHEMA_VALUE
  const records = recordsOf(c)
  const entries = c.check === 'sequence' ? (v.out?.receipts ?? []) : [v.out]
  const results = Object.fromEntries(CHECKS.map((name) => [name, []]))
  const details = []
  const formats = []
  records.forEach((receipt, i) => {
    const payload = receipt.payload ?? {}
    const action = c.actions[i] ? { value: readJson(c.actions[i]), bytes: read(c.actions[i]) } : null
    const where = c.check === 'sequence' ? `line ${i + 1}: ` : ''
    const checked = validate(schema, payload, { assertFormat: mutation?.assertFormat === true })
    if (checked.errors.length) details.push(`${where}${checked.errors.join('; ')}`)
    formats.push(...checked.formats)
    const own = {
      ...receiptChecks(entries[i]),
      schema: checked.errors.length ? 'fail' : 'pass',
      schema_named: schemaNamed(payload, PINNED, { preimage: mutation?.schemaDigest ?? 'bytes' }),
      action_digest: actionDigest(payload, action, { preimage: mutation?.actionDigest ?? 'jcs' }),
      approver_not_agent: approverNotAgent(payload),
      grant_recorded: grantRecorded(payload, grants),
    }
    for (const [name, r] of Object.entries(own)) {
      const result = typeof r === 'string' ? r : r.result
      if (typeof r !== 'string' && result === 'fail') details.push(`${where}${r.detail}`)
      results[name].push(result)
    }
  })
  // (a) The chain: in a sequence, each line after the first must follow the line before it. A receipt alone fails here
  // only if its link is malformed or undecidable; it has no predecessor to follow.
  if (c.check === 'sequence') {
    results.chain.push(...entries.slice(1).map((e) => (e?.checks?.previous ? decides(e.checks.previous.result) : 'not_run')))
    if (v.out?.chainBreaks) results.chain.push('fail')
  } else {
    const link = entries[0]?.checks?.chain_link?.result
    if (link === 'fail' || link === 'undecidable') results.chain.push(link)
  }
  const checks = Object.fromEntries(CHECKS.map((name) => {
    const result = worst(results[name])
    return [name, mutation?.disable === name && result !== 'not_run' ? 'pass' : result]
  }))
  const all = Object.values(checks)
  const outcome = all.includes('fail') ? 'invalid' : all.includes('undecidable') ? 'undecidable' : 'valid'
  const format = formats.length === 0 ? 'none' : formats.every((f) => f.holds) ? 'holds' : 'fails'
  return { checks, outcome, verdict: outcome === 'valid' ? 'ACCEPT' : 'REJECT', format, details }
}

// How the runner's own results differ from the case: every check, the format report, then the verdict (an unsettled
// case: any one of its readings).
function mismatches(c, got) {
  const m = CHECKS.filter((name) => got.checks[name] !== c.expected.checks[name])
    .map((name) => `${name} ${got.checks[name]}, expected ${c.expected.checks[name]}`)
  if (got.format !== c.expected.format) m.push(`format ${got.format}, expected ${c.expected.format}`)
  if (c.kind === 'unsettled') {
    if (!c.readings.some((r) => r.verdict === got.verdict && r.outcome === got.outcome)) m.push(`${got.verdict} (${got.outcome}) is none of its readings`)
  } else if (got.verdict !== c.expected.verdict || got.outcome !== c.expected.outcome) {
    m.push(`${got.verdict} (${got.outcome}), expected ${c.expected.verdict} (${c.expected.outcome})`)
  }
  return m
}

// How the verifier's own report differs from what @veritasacta/verify 0.11.1 reports for the case.
function verifierMismatches(c, v) {
  if (!v.out) return [`no JSON from the verifier (exit ${v.rc})`]
  const subject = c.check === 'sequence' ? (v.out.receipts ?? [])[c.line - 1] ?? {} : v.out
  const code = subject.error && typeof subject.error === 'object' ? subject.error.code : subject.error ?? null
  const where = c.check === 'sequence' ? ` on line ${c.line}` : ''
  const m = []
  if (v.out.outcome !== c.verify.outcome) m.push(`verifier outcome ${v.out.outcome}, expected ${c.verify.outcome}`)
  if (v.rc !== c.verify.exit) m.push(`verifier exit ${v.rc}, expected ${c.verify.exit}`)
  if (code !== c.verify.code) m.push(`verifier code ${code}${where}, expected ${c.verify.code}`)
  if (c.check === 'sequence' && v.out.chains !== c.verify.chains) m.push(`${v.out.chains} chains reported, expected ${c.verify.chains}`)
  if (c.check === 'sequence' && v.out.chainBreaks !== c.verify.chain_breaks) m.push(`${v.out.chainBreaks} chain breaks reported, expected ${c.verify.chain_breaks}`)
  return m
}

console.log(`\n=== cases (${index.cases.length}: ${index.counts.accept} accept, ${index.counts.reject} reject, ${index.counts.unsettled} unsettled) ===`)
console.log('    check kinds: (a) receipt, (b) schema, (c) naming, (d) mi24, the last taken from MI-24\'s text, beyond the schema')
const LABEL = { receipt: 'a', schema: 'b', naming: 'c', mi24: 'd' }
const runs = new Map()
for (const c of index.cases) {
  const args = c.check === 'sequence'
    ? ['--replay-chain', c.file, '--jwks', index.issuer.jwks, '--json']
    : [c.file, '--jwks', index.issuer.jwks, '--mode', 'receipt', '--json']
  const v = verify(args)
  runs.set(c.id, v)
  const got = evaluate(c, v)
  const m = [...verifierMismatches(c, v), ...mismatches(c, got)]
  const notPassing = CHECKS.filter((name) => got.checks[name] === 'fail' || got.checks[name] === 'undecidable')
  const verdict = c.kind === 'unsettled' ? `unsettled (${c.decided_by.map((k) => LABEL[k]).join(', ')}), read as ${got.verdict}` : `${got.verdict} (${got.outcome})`
  const why = notPassing.length ? `: ${notPassing.map((name) => `(${LABEL[KIND_OF[name]]}) ${name} ${got.checks[name]}`).join(', ')}` : ''
  const format = got.format === 'fails' ? '; format date-time would fail if asserted' : ''
  const detail = got.details.length ? ` [${got.details.join('; ')}]` : ''
  if (m.length) bad(`${c.id}: ${verdict}${why}. ${m.join('; ')}`)
  else ok(`${c.id}: ${verdict}${why}${format}${detail}`)
}

// The verifier's reports are fixed now; each mutation re-scores the runner's own checks on them.
console.log('\n=== mutation sweep: checks off, digests over the wrong bytes, format asserted, each enum dropped ===')
const restsOn = (name) => (c) => c.expected.checks[name] === 'fail' || c.expected.checks[name] === 'undecidable'
// Over the wrong bytes, a schema_sha256 that matched stops matching and one naming the RFC 8785 digest starts to: every
// record that names the pinned version with a bare 64-hex digest. A record naming another version fails before its
// digest is compared, and a prefixed digest fails either way.
const comparesSchemaDigest = (c) => recordsOf(c).every((r) => r.payload?.schema_version === PINNED.version && /^[0-9a-f]{64}$/.test(r.payload?.schema_sha256 ?? ''))
function enumPointers(schema, at = '') {
  const found = schema.enum !== undefined ? [at] : []
  for (const [name, sub] of Object.entries(schema.properties ?? {})) found.push(...enumPointers(sub, `${at}/properties/${name}`))
  if (schema.items !== undefined) found.push(...enumPointers(schema.items, `${at}/items`))
  return found
}
function withoutEnum(schema, pointer) {
  const copy = structuredClone(schema)
  const target = pointer.split('/').slice(1).reduce((node, key) => node[key], copy)
  delete target.enum
  return copy
}
const MUTATIONS = [
  ...CHECKS.map((name) => ({ label: `(${LABEL[KIND_OF[name]]}) ${name} turned off`, mutation: { disable: name }, predicted: restsOn(name) })),
  { label: '(c) schema_named over the RFC 8785 form, not the bytes', mutation: { schemaDigest: 'jcs' }, predicted: comparesSchemaDigest },
  { label: '(c) action_digest over the file bytes, not the RFC 8785 form', mutation: { actionDigest: 'file-bytes' }, predicted: (c) => c.expected.checks.action_digest === 'pass' },
  { label: '(b) format asserted', mutation: { assertFormat: true }, predicted: (c) => c.expected.format === 'fails' },
  ...enumPointers(SCHEMA_VALUE).map((pointer) => ({
    label: `(b) the enum at ${pointer} dropped`, mutation: { schema: withoutEnum(SCHEMA_VALUE, pointer) }, predicted: (c) => c.relies_on_enum === pointer,
  })),
]
for (const { label, mutation, predicted } of MUTATIONS) {
  const caught = index.cases.filter((c) => mismatches(c, evaluate(c, runs.get(c.id), mutation)).length).map((c) => c.id)
  const want = index.cases.filter(predicted).map((c) => c.id)
  if (want.length && caught.join() === want.join()) ok(`${label}: ${caught.length} ${caught.length === 1 ? 'case stops' : 'cases stop'} matching (${caught.join(', ')})`)
  else bad(`${label}: ${caught.join(', ') || 'no case'} stopped matching, where ${want.join(', ') || 'at least one case'} should`)
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
