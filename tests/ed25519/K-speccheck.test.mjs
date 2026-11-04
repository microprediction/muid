// ed25519-speccheck cases.json: all 12 rejected, each for the reason K5's order gives from the case's documented
// construction (upstream README condition table: A order, R order, S range, canonicity).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkEd25519, vector, bytes } from './helpers.mjs'

const cases = vector('ed25519-speccheck/cases.json')

const EXPECTED = [
  'key-small-order', // 0: small A and R, S = 0
  'key-small-order', // 1: small A
  'key-mixed-order', // 2: mixed A, small R
  'key-mixed-order', // 3: mixed A and R
  'key-mixed-order', // 4
  'key-mixed-order', // 5
  'sig-s-range', // 6: S > L
  'sig-s-range', // 7: S >> L
  'key-mixed-order', // 8: mixed A, non-canonical R
  'key-mixed-order', // 9
  'key-point', // 10: non-canonical A
  'key-point', // 11: non-canonical A
]

test('there are 12 cases', () => assert.equal(cases.length, 12))

for (let i = 0; i < EXPECTED.length; i++) {
  test(`case ${i} is rejected: ${EXPECTED[i]}`, () => {
    const c = cases[i]
    assert.deepEqual({ ...checkEd25519(c.signature, bytes(c.message), c.pub_key) }, { ok: false, reason: EXPECTED[i] })
  })
}
