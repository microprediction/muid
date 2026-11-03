// P6: everything decode returns is frozen, at every level.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fc, record, shape } from './arbitraries.mjs'
import { encode, decode, deepFrozen } from './helpers.mjs'

test('decoded values are deeply frozen', () => {
  let runs = 0; let nested = 0
  fc.assert(fc.property(record, (v) => {
    runs++
    if (shape(v).containers > 1) nested++
    assert.ok(deepFrozen(decode(encode(v))))
  }))
  assert.ok(nested / runs >= 0.2, `inputs with nested containers: ${nested}/${runs}`)
})

test('a decoded value cannot be modified (modules are strict, so writes throw)', () => {
  const v = decode('{"a":[1,{"b":2}]}')
  assert.throws(() => { v.a[1].b = 3 }, TypeError)
  assert.throws(() => { v.a.push(4) }, TypeError)
  assert.throws(() => { v.c = 1 }, TypeError)
})
