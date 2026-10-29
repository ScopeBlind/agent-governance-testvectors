// Dependency-free checks for the draft FINOS MI-24 decision record vectors.
//
// Two parts:
//   1. validate(): the JSON Schema 2020-12 keywords the draft schema uses, and no others. checkSchema() walks the
//      whole schema first and refuses any other keyword, so an edit that adds one cannot pass unchecked.
//   2. The rules JSON Schema cannot express: the schema named by version and by the SHA-256 of its bytes, the
//      resolved action digest, and the two contradictions between fields that MI-24 names and its fields can show.
//
// Each rule returns { result, detail }, result one of pass, fail, not_run (the rule does not apply to this record).

import crypto from 'node:crypto'
import { canonicalize } from '../../evidence-predicate/lib.mjs'

const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description'])
const ASSERTIONS = new Set(['type', 'required', 'properties', 'items', 'anyOf', 'const', 'minLength', 'minProperties', 'pattern'])
const TYPES = new Set(['string', 'number', 'object', 'array', 'boolean', 'null'])

// Refuse a schema that uses a keyword or a type name validate() does not implement.
export function checkSchema(schema, at = '#') {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) throw new Error(`${at}: a schema must be an object`)
  for (const key of Object.keys(schema)) {
    if (!ANNOTATIONS.has(key) && !ASSERTIONS.has(key)) throw new Error(`${at}: keyword ${key} is not implemented here`)
  }
  for (const t of [schema.type ?? []].flat()) if (!TYPES.has(t)) throw new Error(`${at}: type ${t} is not implemented here`)
  for (const [name, sub] of Object.entries(schema.properties ?? {})) checkSchema(sub, `${at}/properties/${name}`)
  if (schema.items !== undefined) checkSchema(schema.items, `${at}/items`)
  for (const [i, sub] of (schema.anyOf ?? []).entries()) checkSchema(sub, `${at}/anyOf/${i}`)
}

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v)

// The errors of instance against schema, as JSON Pointer locations with a reason; none means it validates.
export function validate(schema, instance, at = '') {
  const where = at || '/'
  const t = typeOf(instance)
  if (schema.type !== undefined) {
    const types = [schema.type].flat()
    if (!types.includes(t)) return [`${where}: ${t}, where the schema allows ${types.join(' or ')}`]
  }
  const errors = []
  if (schema.const !== undefined && canonicalize(schema.const) !== canonicalize(instance)) {
    errors.push(`${where}: ${JSON.stringify(instance)}, where the schema requires ${JSON.stringify(schema.const)}`)
  }
  if (t === 'string') {
    if (schema.minLength !== undefined && [...instance].length < schema.minLength) errors.push(`${where}: shorter than ${schema.minLength}`)
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(instance)) errors.push(`${where}: ${JSON.stringify(instance)} does not match the schema's pattern`)
  }
  if (t === 'object') {
    if (schema.minProperties !== undefined && Object.keys(instance).length < schema.minProperties) errors.push(`${where}: fewer than ${schema.minProperties} members`)
    for (const name of schema.required ?? []) if (!Object.hasOwn(instance, name)) errors.push(`${at}/${name}: required, and absent`)
    for (const [name, sub] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(instance, name)) errors.push(...validate(sub, instance[name], `${at}/${name}`))
    }
  }
  if (t === 'array' && schema.items !== undefined) instance.forEach((item, i) => errors.push(...validate(schema.items, item, `${at}/${i}`)))
  if (schema.anyOf !== undefined && !schema.anyOf.some((sub) => validate(sub, instance, at).length === 0)) {
    errors.push(`${where}: matches none of ${schema.anyOf.map((s) => JSON.stringify(s)).join(', ')}`)
  }
  return errors
}

const pass = (detail) => ({ result: 'pass', detail })
const fail = (detail) => ({ result: 'fail', detail })
const notRun = (detail) => ({ result: 'not_run', detail })
export const sha256Prefixed = (bytes) => `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`

// MI-24: "Each record names its schema by version and by the SHA-256 digest of the schema's bytes." The bytes are the
// schema file as published, not its RFC 8785 form. preimage 'jcs' exists only for run.mjs's mutation sweep.
export function schemaNamed(payload, schema, { preimage = 'bytes' } = {}) {
  if (typeof payload.schema_version !== 'string' || typeof payload.schema_digest !== 'string') {
    return fail('the record does not name its schema by version and digest')
  }
  if (payload.schema_version !== schema.version) return fail(`it names version ${payload.schema_version}; the schema is ${schema.version}`)
  const want = preimage === 'jcs'
    ? sha256Prefixed(Buffer.from(canonicalize(JSON.parse(schema.bytes.toString('utf8'))), 'utf8'))
    : sha256Prefixed(schema.bytes)
  if (payload.schema_digest !== want) return fail(`it names ${payload.schema_digest}; the schema's bytes hash to ${want}`)
  return pass(`version ${schema.version}, digest of the schema's bytes`)
}

// MI-24: "Compute resolved_action_digest as SHA-256 over the RFC 8785 (JCS) bytes of the resolved action." action is
// { value, bytes }: the parsed action file and its bytes. preimage 'file-bytes' exists only for the mutation sweep.
export function actionDigest(payload, action, { preimage = 'jcs' } = {}) {
  if (!action) return notRun('no resolved action supplied')
  if (typeof payload.resolved_action_digest !== 'string') return notRun('the record carries no resolved_action_digest to compare')
  const want = preimage === 'file-bytes' ? sha256Prefixed(action.bytes) : sha256Prefixed(Buffer.from(canonicalize(action.value), 'utf8'))
  if (payload.resolved_action_digest !== want) return fail(`it names ${payload.resolved_action_digest}; the supplied action hashes to ${want}`)
  return pass('the digest of the supplied action')
}

// MI-24 Checkable Decision Records: "an approval whose human_approver.principal_id equals agent_id" is invalid. No member
// MI-24 lists says that a record is an approval, so this applies to every record that names a human approver, on Key
// Principles: "In every pattern the agent itself is never a valid approver." Equality is exact.
export function approverNotAgent(payload) {
  const approver = payload.human_approver
  if (!approver || typeof approver !== 'object' || typeof approver.principal_id !== 'string' || typeof payload.agent_id !== 'string') {
    return notRun('the record names no human approver and agent to compare')
  }
  if (approver.principal_id === payload.agent_id) return fail(`human_approver.principal_id is agent_id, ${payload.agent_id}`)
  return pass('the approver is not the agent')
}

// MI-24 Checkable Decision Records: "a grant_id that resolves to no recorded standing approval" is invalid. grants is
// the set of grant_id values the institution recorded; a null grant_id (a per-action decision) names none.
export function grantRecorded(payload, grants) {
  const approver = payload.human_approver
  if (!approver || typeof approver !== 'object' || typeof approver.grant_id !== 'string') return notRun('the record names no grant')
  if (!grants.has(approver.grant_id)) return fail(`grant_id ${approver.grant_id} resolves to no recorded standing approval`)
  return pass(`grant_id ${approver.grant_id} is recorded`)
}
