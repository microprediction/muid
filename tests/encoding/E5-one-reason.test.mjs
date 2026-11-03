// E5: a value with several violations is always refused for the same one, found in the order SPEC §3 defines.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, refuses } from './helpers.mjs'

const sym = Symbol('s')

const CASES = [
  ['members are visited in canonical key order', () => ({ b: null, a: 1.5 }), 'float'],
  ['an uppercase key sorts before lowercase ones', () => ({ a: null, B: 1 }), 'key'],
  ['a key is checked before its value', () => ({ A: null }), 'key'],
  ['grammar is checked before the descriptor', () => Object.defineProperty({}, 'A', { get () { return 1 }, enumerable: true }), 'key'],
  ['the descriptor is checked before the value', () => Object.defineProperty({}, 'a', { value: null, enumerable: false }), 'non-enumerable'],
  ['array elements are visited in index order', () => ({ a: [null, 1.5] }), 'null'],
  ['container shape is checked before members', () => ({ a: [null, , 1] }), 'array-shape'], // eslint-disable-line no-sparse-arrays
  ['symbol keys are checked before string keys', () => ({ A: 1, [sym]: 1 }), 'symbol-key'],
  ['depth is checked on entry, before contents', () => { let v = { a: null }; for (let i = 1; i < 17; i++) v = { a: v }; return v }, 'depth'],
  ['a cycle is reported as a cycle', () => { const o = { a: {} }; o.a.b = o; return o }, 'cycle'],
  ['the top level is checked first', () => [null, 1.5], 'top-level'],
  ['NaN is non-finite, not a float', () => ({ a: NaN }), 'non-finite'],
  ['-0 is reported before anything else about it', () => ({ a: -0 }), 'negative-zero'],
  ['size stops encoding before a later violation', () => ({ a: 'x'.repeat(70000), b: null }), 'size'],
  ['an earlier violation is found before size', () => ({ a: null, b: 'x'.repeat(70000) }), 'null'],
]

test('one-reason case count', () => {
  assert.equal(CASES.length, 15)
})

for (const [label, make, reason] of CASES) {
  test(label, () => refuses(() => encode(make()), reason, label))
}
