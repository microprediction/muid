import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { envelope } from '../impl.mjs'

export const env = envelope

// SPEC §4 V2 and V4.
export const TYPES = Object.freeze(['root', 'delegation', 'attestation', 'membership', 'freeze', 'contest', 'anchor', 'settlement', 'head', 'claim',
  'revocation', 'receipt', 'logged'])
export const REASONS = Object.freeze(['envelope-encoding', 'envelope-shape', 'payload-size', 'payload-encoding', 'payload-shape', 'version', 'type'])
export const MAX_PAYLOAD = 49152
export const PREFIX = 'muid/v1\n'

// Independent of the implementation and of @noble/hashes.
export const oracleId = (payload) => createHash('sha256').update(PREFIX + payload, 'utf8').digest('hex')

// Builds envelope text by hand, without the implementation: JSON.stringify of a one- or two-key object in canonical
// key order is its JCS form when the values are a string and a canonical object.
export function envelopeText (payload, sig) {
  return sig === undefined ? `{"payload":${JSON.stringify(payload)}}` : `{"payload":${JSON.stringify(payload)},"sig":${sig}}`
}

// The JCS form of {v, type, body} for a canonical body text.
export const payloadText = (type, bodyText = '{}', v = '1') => `{"body":${bodyText},"type":${JSON.stringify(type)},"v":${v}}`

export function refuses (fn, reason, label) {
  assert.ok(REASONS.includes(reason), `${label}: test bug, unknown reason ${reason}`)
  let returned
  try {
    returned = fn()
  } catch (e) {
    assert.ok(env.EnvelopeError.isRefusal(e), `${label}: expected EnvelopeError, got ${e?.constructor?.name}: ${e?.message}`)
    assert.equal(e.reason, reason, `${label}: wrong reason`)
    return
  }
  assert.fail(`${label}: expected refusal "${reason}", but it returned ${String(returned)}`)
}

export function deepFrozen (v) {
  if (v === null || typeof v !== 'object') return true
  if (!Object.isFrozen(v)) return false
  return Object.values(v).every(deepFrozen)
}
