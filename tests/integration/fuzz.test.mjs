// Fuzzing the verifier (SPEC §12): random changes to the records a claim rests on, beyond the tamper sweep's single
// characters. Several edits at once; a value inside a record changed and the record re-encoded canonically under its
// old signature; records swapped between fields; any JavaScript value in place of a record. Whatever is changed, both
// verifyClaim and verifyDelegation refuse it with a reason, and neither throws. The nightly job runs this, with every
// property test, at FC_SCALE times its usual run count and a new FC_SEED; fast-check reports the seed and path of any
// failure, to replay it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { v, RECORDS, CALL } from './records.mjs'
import { envelope, encoding } from '../impl.mjs'
import { runs } from '../runs.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261107)
const RUNS = runs(200)
const NAMES = Object.keys(RECORDS)
const REASON = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/

// Both entry points on the changed records, neither throwing: verifyClaim refuses with a well-formed reason, and so
// does verifyDelegation unless only the claim, which it does not read, was changed.
function refusedBoth (records, what) {
  const onlyClaim = NAMES.every((n) => n === 'claim' || records[n] === RECORDS[n])
  for (const verify of onlyClaim ? [v.verifyClaim] : [v.verifyClaim, v.verifyDelegation]) {
    let r
    assert.doesNotThrow(() => { r = verify(records, CALL) }, what)
    assert.equal(r.ok, false, `accepted: ${what}`)
    assert.match(r.reason, REASON, what)
  }
  if (onlyClaim) assert.doesNotThrow(() => v.verifyDelegation(records, CALL), what)
}
const changed = (name, text) => text !== RECORDS[name]

test('the unchanged records verify', () => {
  assert.equal(v.verifyClaim(RECORDS, CALL).ok, true)
  assert.equal(v.verifyDelegation(RECORDS, CALL).ok, true)
})

// Characters an edit may put in: JSON's own, hex digits, escapes, and some that encoders treat specially.
const CHARS = fc.constantFrom(...'{}[]":,\\ 0123456789abcdefABCDEFxnu-+.eE', '\u0000', ' ', '\ud800', 'é', '﻿', '\n')
const edit = fc.record({ kind: fc.constantFrom('replace', 'insert', 'delete', 'repeat'), at: fc.nat(), ch: CHARS, len: fc.integer({ min: 1, max: 40 }) })
function apply (text, e) {
  const i = e.at % (text.length + 1)
  if (e.kind === 'replace') return text.slice(0, i) + e.ch + text.slice(i + 1)
  if (e.kind === 'insert') return text.slice(0, i) + e.ch + text.slice(i)
  if (e.kind === 'delete') return text.slice(0, i) + text.slice(i + e.len)
  return text.slice(0, i) + text.slice(i, i + e.len) + text.slice(i) // a stretch repeated
}

test('several edits to one record, or to several, are refused', () => {
  fc.assert(fc.property(fc.array(fc.record({ name: fc.constantFrom(...NAMES), edits: fc.array(edit, { minLength: 1, maxLength: 4 }) }),
    { minLength: 1, maxLength: 3 }), (changes) => {
    const records = { ...RECORDS }
    for (const { name, edits } of changes) records[name] = edits.reduce(apply, records[name])
    fc.pre(NAMES.some((n) => changed(n, records[n])))
    refusedBoth(records, JSON.stringify(changes))
  }), { seed: SEED, numRuns: RUNS })
})

// A value somewhere in a record's payload or signature, replaced; the payload re-encoded canonically (so it is not
// refused merely as non-canonical) and kept with its old signature.
function paths (x, at = []) {
  if (x === null || typeof x !== 'object') return [at]
  return [at, ...Object.keys(x).flatMap((k) => paths(x[k], [...at, k]))]
}
function setAt (x, path, value) {
  if (path.length === 0) return value
  const copy = Array.isArray(x) ? [...x] : { ...x }
  copy[path[0]] = setAt(x[path[0]], path.slice(1), value)
  return copy
}
const near = (x) => typeof x === 'number' ? fc.constantFrom(x + 1, x - 1, -x, 0)
  : typeof x === 'string' ? fc.constantFrom(x + 'a', x.slice(1), x.toUpperCase(), '', x.replace(/./, '0'))
    : Array.isArray(x) ? fc.constantFrom([], [...x, ...x], x.slice(1))
      : fc.constant(null)
const LEAF = fc.oneof(fc.jsonValue({ maxDepth: 2 }), fc.constantFrom(-0, 2 ** 53, 1e21, 0.5, '', '0'.repeat(64)))

test('a value inside a record changed, the record re-encoded under its old signature, is refused', () => {
  fc.assert(fc.property(fc.constantFrom(...NAMES), fc.nat(), fc.boolean(), fc.nat(), LEAF, (name, pick, inPayload, n, leaf) => {
    const outer = JSON.parse(RECORDS[name])
    const inner = JSON.parse(outer.payload)
    const target = inPayload || outer.sig === undefined ? inner : outer.sig
    const all = paths(target)
    const path = all[pick % all.length]
    const old = path.reduce((x, k) => x[k], target)
    const value = fc.sample(fc.oneof(near(old), fc.constant(leaf)), { seed: n, numRuns: 1 })[0]
    let text
    try {
      text = target === inner
        ? envelope.wrap(encoding.encode(setAt(inner, path, value)), outer.sig)
        : envelope.wrap(outer.payload, setAt(outer.sig, path, value))
    } catch { fc.pre(false) } // a value the encoder refuses cannot be sent canonically
    fc.pre(changed(name, text))
    refusedBoth({ ...RECORDS, [name]: text }, `${name} ${JSON.stringify(path)} = ${JSON.stringify(value)}`)
  }), { seed: SEED, numRuns: RUNS })
})

test('records given in one another\'s places are refused', () => {
  fc.assert(fc.property(fc.shuffledSubarray(NAMES, { minLength: 2 }), fc.nat(), (names, shift) => {
    const records = { ...RECORDS }
    const k = 1 + (shift % (names.length - 1))
    names.forEach((n, i) => { records[n] = RECORDS[names[(i + k) % names.length]] })
    refusedBoth(records, names.join(' '))
  }), { seed: SEED, numRuns: RUNS })
})

test('any JavaScript value in place of a record is refused, never thrown on', () => {
  fc.assert(fc.property(fc.constantFrom(...NAMES), fc.anything({ withBigInt: true, withDate: true, withMap: true, withSet: true,
    withTypedArray: true, withSparseArray: true, withNullPrototype: true, withObjectString: true }), (name, value) => {
    fc.pre(value !== RECORDS[name])
    refusedBoth({ ...RECORDS, [name]: value }, `${name}: ${fc.stringify(value)}`)
  }), { seed: SEED, numRuns: RUNS })
  for (const records of [undefined, null, 0, '', [], () => {}]) {
    for (const verify of [v.verifyClaim, v.verifyDelegation]) {
      let r
      assert.doesNotThrow(() => { r = verify(records, CALL) })
      assert.equal(r.ok, false)
    }
  }
})
