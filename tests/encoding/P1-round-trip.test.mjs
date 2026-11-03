// P1 (E1): for every in-domain record, decode(encode(v)) equals v.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fc, record, shape } from './arbitraries.mjs'
import { encode, decode } from './helpers.mjs'

test('round trip', () => {
  let runs = 0; let deep = 0; let nonAscii = 0
  fc.assert(fc.property(record, (v) => {
    runs++
    const s = shape(v)
    if (s.depth >= 3) deep++
    if (s.nonAscii) nonAscii++
    assert.deepStrictEqual(decode(encode(v)), v)
  }))
  // Anti-vacuity: the inputs were not all shallow or all ASCII.
  assert.ok(deep / runs >= 0.1, `nested inputs: ${deep}/${runs}`)
  assert.ok(nonAscii / runs >= 0.1, `non-ASCII inputs: ${nonAscii}/${runs}`)
})
