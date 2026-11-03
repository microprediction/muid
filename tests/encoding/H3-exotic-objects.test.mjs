// E3: an object with internal slots is not plain data even when its prototype has been replaced so that it looks
// plain. Found by adversarial review: before the fix all of these encoded as {} — silently dropping the slot's data.
//
// Detection uses only checks that are cheap for ordinary objects (Object.prototype.toString's built-in tag and
// ArrayBuffer.isView). The kinds that can be told from {} only by exception-throwing brand checks are a documented
// residual (SPEC §3): checking them would slow every plain object about a thousandfold, and producing one requires code
// in the page to re-prototype it deliberately — never decode, and never a Proxy, which has no internal slots. The
// residual is pinned below so that any change in it is noticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, refuses } from './helpers.mjs'

const asPlain = (v) => Object.setPrototypeOf(v, Object.prototype)
const asNull = (v) => Object.setPrototypeOf(v, null)

const DETECTED = [
  ['Number wrapper', () => new Number(5)], // eslint-disable-line no-new-wrappers
  ['String wrapper', () => new String('')], // eslint-disable-line no-new-wrappers
  ['Boolean wrapper', () => new Boolean(true)], // eslint-disable-line no-new-wrappers
  ['Date', () => new Date(0)],
  ['RegExp', () => /x/],
  ['Error', () => new Error('e')],
  ['arguments', function () { return arguments }],
  ['Uint8Array', () => new Uint8Array(0)],
  ['DataView', () => new DataView(new ArrayBuffer(1))],
]

const RESIDUAL = [
  ['Symbol wrapper', () => Object(Symbol('s'))],
  ['BigInt wrapper', () => Object(1n)],
  ['Map', () => new Map([[1, 2]])],
  ['Set', () => new Set([1])],
  ['WeakMap', () => new WeakMap()],
  ['WeakSet', () => new WeakSet()],
  ['WeakRef', () => new WeakRef({})],
  ['ArrayBuffer', () => new ArrayBuffer(8)],
  ['SharedArrayBuffer', () => new SharedArrayBuffer(8)],
]

test('exotic case counts', () => {
  assert.equal(DETECTED.length, 9)
  assert.equal(RESIDUAL.length, 9)
})

for (const [name, make] of DETECTED) {
  test(`${name} with Object.prototype is not plain`, () => refuses(() => encode({ a: asPlain(make()) }), 'non-plain', name))
  test(`${name} with a null prototype is not plain`, () => refuses(() => encode({ a: asNull(make()) }), 'non-plain', name))
  test(`${name} disguised as plain at the top level`, () => refuses(() => encode(asPlain(make())), 'top-level', name))
}

for (const [name, make] of RESIDUAL) {
  test(`residual: ${name} given a plain prototype encodes as its own properties`, () => {
    assert.equal(encode({ a: asPlain(make()) }), '{"a":{}}')
  })
  test(`${name} with its own prototype is not plain`, () => refuses(() => encode({ a: make() }), 'non-plain', name))
}

// A Promise depends on the host: Node attaches own symbol properties to promises while async hooks are active (as under
// the test runner), so a disguised Promise is either refused for its symbol key or encodes as {}. Both are pinned.
test('residual: a Promise given a plain prototype is refused for a symbol key or encodes as its own properties', () => {
  let outcome
  try {
    outcome = encode({ a: asPlain(Promise.resolve()) })
  } catch (e) {
    outcome = e.reason
  }
  assert.ok(outcome === '{"a":{}}' || outcome === 'symbol-key', String(outcome))
  refuses(() => encode({ a: Promise.resolve() }), 'non-plain', 'Promise with its own prototype')
})

test('a real plain object and a null-prototype object still encode', () => {
  assert.equal(encode({ a: { b: 1 } }), '{"a":{"b":1}}')
  assert.equal(encode({ a: Object.assign(Object.create(null), { b: 1 }) }), '{"a":{"b":1}}')
})
