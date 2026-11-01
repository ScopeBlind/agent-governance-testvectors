// Dependency-free checks for the FINOS MI-24 decision record vectors, which test the A-DoA Decision Record Schema
// v1.1.0 (Swosti Panda, CC BY 4.0) on records carried as Veritas Acta receipts.
//
//   validate()        the JSON Schema 2020-12 keywords the vendored schema uses, and no others. checkSchema() walks the
//                     whole schema first and refuses any other keyword, so a schema that needs one fails loudly.
//                     format is an annotation, as 2020-12 has it by default: it never decides the result unless the
//                     caller asks for it to be asserted, and every date-time it reaches is reported either way.
//   schemaNamed() and actionDigest()        (c) the schema's name and the digests, against the pinned bytes
//   approverNotAgent() and grantRecorded()  (d) checks taken from MI-24's text, beyond the schema
//
// Each rule returns { result, detail }, result one of pass, fail, not_run (the rule does not apply to this record).

import crypto from 'node:crypto'
import { canonicalize } from '../../evidence-predicate/lib.mjs'

const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', 'format'])
const ASSERTIONS = new Set(['type', 'required', 'properties', 'items', 'enum', 'const', 'pattern', 'minimum'])
const TYPES = new Set(['string', 'number', 'object', 'array', 'boolean', 'null'])
const FORMATS = { 'date-time': (value) => dateTimeHolds(value) }

// Refuse a schema that uses a keyword, a type or a format validate() does not implement.
export function checkSchema(schema, at = '#') {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) throw new Error(`${at}: a schema must be an object`)
  for (const key of Object.keys(schema)) {
    if (!ANNOTATIONS.has(key) && !ASSERTIONS.has(key)) throw new Error(`${at}: keyword ${key} is not implemented here`)
  }
  for (const t of [schema.type ?? []].flat()) if (!TYPES.has(t)) throw new Error(`${at}: type ${t} is not implemented here`)
  if (schema.format !== undefined && !Object.hasOwn(FORMATS, schema.format)) throw new Error(`${at}: format ${schema.format} is not implemented here`)
  for (const [name, sub] of Object.entries(schema.properties ?? {})) checkSchema(sub, `${at}/properties/${name}`)
  if (schema.items !== undefined) checkSchema(schema.items, `${at}/items`)
}

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v)

// { errors, formats }: errors are the assertion failures, as JSON Pointer locations with a reason (none means the
// instance validates); formats lists each string a format reached, and whether its value satisfies it. With
// assertFormat, a value that does not satisfy its format is an error too.
export function validate(schema, instance, { assertFormat = false } = {}) {
  const out = { errors: [], formats: [] }
  walk(schema, instance, '', out, assertFormat)
  return out
}

function walk(schema, instance, at, out, assertFormat) {
  const where = at || '/'
  const t = typeOf(instance)
  if (schema.type !== undefined) {
    const types = [schema.type].flat()
    if (!types.includes(t)) { out.errors.push(`${where}: ${t}, where the schema allows ${types.join(' or ')}`); return }
  }
  if (schema.enum !== undefined && !schema.enum.some((v) => canonicalize(v) === canonicalize(instance))) {
    out.errors.push(`${where}: ${JSON.stringify(instance)} is not one of the schema's values`)
  }
  if (schema.const !== undefined && canonicalize(schema.const) !== canonicalize(instance)) {
    out.errors.push(`${where}: ${JSON.stringify(instance)}, where the schema requires ${JSON.stringify(schema.const)}`)
  }
  if (t === 'string') {
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(instance)) out.errors.push(`${where}: ${JSON.stringify(instance)} does not match the schema's pattern`)
    if (schema.format !== undefined) {
      const holds = FORMATS[schema.format](instance)
      out.formats.push({ at: where, format: schema.format, holds })
      if (assertFormat && !holds) out.errors.push(`${where}: ${JSON.stringify(instance)} is not a ${schema.format}`)
    }
  }
  if (t === 'number' && schema.minimum !== undefined && instance < schema.minimum) out.errors.push(`${where}: ${instance} is below ${schema.minimum}`)
  if (t === 'object') {
    for (const name of schema.required ?? []) if (!Object.hasOwn(instance, name)) out.errors.push(`${at}/${name}: required, and absent`)
    for (const [name, sub] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(instance, name)) walk(sub, instance[name], `${at}/${name}`, out, assertFormat)
    }
  }
  if (t === 'array' && schema.items !== undefined) instance.forEach((item, i) => walk(schema.items, item, `${at}/${i}`, out, assertFormat))
}

// RFC 3339 section 5.6 date-time: full-date, T, full-time with an offset (Z or +hh:mm). T and Z in either case. The day
// must exist in its month, and a leap second (:60) is read as ajv-formats reads section 5.7: only at 23:59 UTC.
const DATE_TIME = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))$/
export function dateTimeHolds(value) {
  const m = DATE_TIME.exec(value)
  if (!m) return false
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number)
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
  if (!days || d < 1 || d > days || h > 23 || mi > 59 || s > 60) return false
  const [oh, om] = m[7] ? [0, 0] : [Number(m[9]), Number(m[10])]
  if (oh > 23 || om > 59) return false
  if (s === 60) {
    const sign = m[8] === '-' ? -1 : 1
    if ((((h * 60 + mi - sign * (oh * 60 + om)) % 1440) + 1440) % 1440 !== 23 * 60 + 59) return false
  }
  return true
}

const pass = (detail) => ({ result: 'pass', detail })
const fail = (detail) => ({ result: 'fail', detail })
const notRun = (detail) => ({ result: 'not_run', detail })
const sha256Hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex')

// (c) The record names its schema: schema_version is the pinned schema's version, and schema_sha256 is the SHA-256 of
// the pinned file's bytes. The schema states no encoding for schema_sha256; these vectors use lowercase hex, 64
// characters, no prefix, and hold every record to it. preimage 'jcs' exists only for run.mjs's mutation sweep.
export function schemaNamed(payload, schema, { preimage = 'bytes' } = {}) {
  if (typeof payload.schema_version !== 'string' || typeof payload.schema_sha256 !== 'string') {
    return fail('the record does not name its schema by version and digest')
  }
  if (payload.schema_version !== schema.version) return fail(`it names version ${payload.schema_version}; the pinned schema is ${schema.version}`)
  const want = preimage === 'jcs' ? sha256Hex(Buffer.from(canonicalize(JSON.parse(schema.bytes.toString('utf8'))), 'utf8')) : sha256Hex(schema.bytes)
  if (payload.schema_sha256 !== want) return fail(`it names ${payload.schema_sha256}; the pinned schema's bytes hash to ${want}`)
  return pass(`version ${schema.version}, the digest of the pinned bytes`)
}

// (c) resolved_action_digest names the action supplied: the SHA-256 over the RFC 8785 (JCS) bytes of the resolved action
// and arguments, as the schema's description has it. Its form ("sha256:" and lowercase hex) is the schema's pattern, so
// (b) decides that; this compares the value alone. action is { value, bytes }: the parsed action file and its bytes.
// preimage 'file-bytes' exists only for the mutation sweep.
export function actionDigest(payload, action, { preimage = 'jcs' } = {}) {
  if (!action) return notRun('no resolved action supplied')
  if (typeof payload.resolved_action_digest !== 'string') return notRun('the record carries no resolved_action_digest to compare')
  const named = /^(?:sha256:)?([0-9a-fA-F]{64})$/.exec(payload.resolved_action_digest)
  if (!named) return fail(`${payload.resolved_action_digest} is not a SHA-256 digest`)
  const want = preimage === 'file-bytes' ? sha256Hex(action.bytes) : sha256Hex(Buffer.from(canonicalize(action.value), 'utf8'))
  if (named[1].toLowerCase() !== want) return fail(`it names ${payload.resolved_action_digest}; the supplied action hashes to sha256:${want}`)
  return pass('the digest of the supplied action')
}

// (d) MI-24 Checkable Decision Records: "an approval whose human_approver.principal_id equals agent_id" is invalid. The
// schema has no member that says a record is an approval, so this applies to every record that names a human approver,
// on MI-24's Key Principles: "In every pattern the agent itself is never a valid approver." Equality is exact.
export function approverNotAgent(payload) {
  const approver = payload.human_approver
  if (!approver || typeof approver !== 'object' || typeof approver.principal_id !== 'string' || typeof payload.agent_id !== 'string') {
    return notRun('the record names no human approver and agent to compare')
  }
  if (approver.principal_id === payload.agent_id) return fail(`human_approver.principal_id is agent_id, ${payload.agent_id}`)
  return pass('the approver is not the agent')
}

// (d) MI-24 Checkable Decision Records: "a grant_id that resolves to no recorded standing approval" is invalid. The schema
// requires grant_id on every record, including a per-action decision, so this reads it only where the oversight
// pattern rests on a standing grant: STANDING_BOUNDED_GRANT and UNATTENDED_T2. grants is the set of grant_id values the
// institution recorded.
export const STANDING_PATTERNS = new Set(['STANDING_BOUNDED_GRANT', 'UNATTENDED_T2'])
export function grantRecorded(payload, grants) {
  const approver = payload.human_approver
  if (!approver || typeof approver !== 'object' || typeof approver.grant_id !== 'string') return notRun('the record names no grant')
  if (!STANDING_PATTERNS.has(approver.oversight_pattern)) return notRun(`${approver.oversight_pattern} rests on no standing grant`)
  if (!grants.has(approver.grant_id)) return fail(`grant_id ${approver.grant_id} resolves to no recorded standing approval`)
  return pass(`grant_id ${approver.grant_id} is recorded`)
}
