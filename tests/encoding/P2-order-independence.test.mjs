// P2 (E1, E5): key insertion order at any level never changes the encoding.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fc, record, reorder } from './arbitraries.mjs'
import { encode } from './helpers.mjs'

test('order independence', () => {
  let runs = 0; let reordered = 0
  fc.assert(fc.property(record, fc.nat(), (v, seed) => {
    runs++
    const w = reorder(v, seed)
    if (JSON.stringify(w) !== JSON.stringify(v)) reordered++
    assert.equal(encode(w), encode(v))
  }))
  // Anti-vacuity: a real share of runs actually changed the insertion order.
  assert.ok(reordered / runs >= 0.2, `reordered inputs: ${reordered}/${runs}`)
})
