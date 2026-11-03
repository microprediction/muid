import assert from 'node:assert/strict'
import { encoding } from '../impl.mjs'

export const { encode, decode, EncodingError, MAX_BYTES, MAX_DEPTH } = encoding

// SPEC §3 E5: the complete set of reason codes.
export const REASONS = Object.freeze([
  'top-level', 'key', 'symbol-key', 'accessor', 'non-enumerable', 'non-plain', 'array-shape', 'cycle', 'depth',
  'size', 'null', 'undefined', 'non-finite', 'negative-zero', 'float', 'unsafe-integer', 'type', 'surrogate',
  'syntax', 'non-canonical',
])

// Asserts that fn throws an EncodingError carrying exactly `reason`. A refusal for the wrong reason fails.
export function refuses (fn, reason, label) {
  assert.ok(REASONS.includes(reason), `${label}: test bug, unknown reason ${reason}`)
  let returned
  try {
    returned = fn()
  } catch (e) {
    assert.ok(e instanceof EncodingError, `${label}: expected EncodingError, got ${e?.constructor?.name}: ${e?.message}`)
    assert.equal(e.reason, reason, `${label}: wrong reason`)
    return
  }
  assert.fail(`${label}: expected refusal "${reason}", but it returned ${JSON.stringify(returned)}`)
}

// Every object and array reachable from v is frozen.
export function deepFrozen (v) {
  if (v === null || typeof v !== 'object') return true
  if (!Object.isFrozen(v)) return false
  return Object.values(v).every(deepFrozen)
}
