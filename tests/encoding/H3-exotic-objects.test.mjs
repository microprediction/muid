// E3: an object with internal slots is not plain data even when its prototype has been replaced, so that it looks
// plain. Before the fix these encoded as {} — silently dropping the slot's data. Found by adversarial review.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, refuses } from './helpers.mjs'

const asPlain = (v) => Object.setPrototypeOf(v, Object.prototype)
const asNull = (v) => Object.setPrototypeOf(v, null)

const CASES = [
  ['Number', () => new Number(5)], // eslint-disable-line no-new-wrappers
  ['String', () => new String('')], // eslint-disable-line no-new-wrappers
  ['Boolean', () => new Boolean(true)], // eslint-disable-line no-new-wrappers
  ['Symbol wrapper', () => Object(Symbol('s'))],
  ['BigInt wrapper', () => Object(1n)],
  ['Date', () => new Date(0)],
  ['RegExp', () => /x/],
  ['Map', () => new Map([[1, 2]])],
  ['Set', () => new Set([1])],
  ['WeakMap', () => new WeakMap()],
  ['WeakSet', () => new WeakSet()],
  ['WeakRef', () => new WeakRef({})],
  ['ArrayBuffer', () => new ArrayBuffer(8)],
  ['Uint8Array', () => new Uint8Array(0)],
  ['DataView', () => new DataView(new ArrayBuffer(1))],
]

test('exotic case count', () => {
  assert.equal(CASES.length, 15)
})

for (const [name, make] of CASES) {
  test(`${name} with Object.prototype is not plain`, () => refuses(() => encode({ a: asPlain(make()) }), 'non-plain', name))
  test(`${name} with a null prototype is not plain`, () => refuses(() => encode({ a: asNull(make()) }), 'non-plain', name))
  test(`${name} disguised as plain at the top level`, () => refuses(() => encode(asPlain(make())), 'top-level', name))
}

test('a real plain object and a null-prototype object still encode', () => {
  assert.equal(encode({ a: { b: 1 } }), '{"a":{"b":1}}')
  assert.equal(encode({ a: Object.assign(Object.create(null), { b: 1 }) }), '{"a":{"b":1}}')
})
