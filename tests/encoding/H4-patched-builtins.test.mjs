// E7: the encoder uses only built-ins it captured when it was loaded, so code that patches a built-in afterwards
// cannot change any result. Found by adversarial review: a patched RegExp.prototype.exec let the key
// 'a":1,"b' through unescaped, so {'a":1,"b': 2} encoded to the same bytes as {a: 1, b: 2} (an E1 collision).
//
// Results are captured inside the patched window and asserted only after everything is restored, because the
// assertion library itself uses the same built-ins.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, decode, EncodingError, deepFrozen } from './helpers.mjs'

const LONE = String.fromCharCode(0xd800)

function underPatch (target, name, value, fn) {
  const saved = Object.getOwnPropertyDescriptor(target, name)
  Object.defineProperty(target, name, { ...saved, value })
  let result
  try {
    result = { value: fn() }
  } catch (error) {
    result = { error }
  } finally {
    Object.defineProperty(target, name, saved)
  }
  return result
}

const refusedWith = (r, reason) => {
  assert.ok(r.error instanceof EncodingError, `expected EncodingError, got ${r.error ?? JSON.stringify(r.value)}`)
  assert.equal(r.error.reason, reason)
}

const CASES = [
  ['RegExp.prototype.exec', RegExp.prototype, 'exec', function (s) { return [s] },
    () => encode({ 'a":1,"b': 2 }), (r) => refusedWith(r, 'key')],
  ['RegExp.prototype.test', RegExp.prototype, 'test', () => true,
    () => encode({ 'a":1,"b': 2 }), (r) => refusedWith(r, 'key')],
  ['String.prototype.isWellFormed', String.prototype, 'isWellFormed', () => true,
    () => encode({ a: LONE }), (r) => refusedWith(r, 'surrogate')],
  ['Array.prototype.sort', Array.prototype, 'sort', function () { return this },
    () => encode({ b: 1, a: 2 }), (r) => assert.equal(r.value, '{"a":2,"b":1}')],
  ['Array.prototype.sort, decode side', Array.prototype, 'sort', function () { return this },
    () => decode('{"b":1,"a":2}'), (r) => refusedWith(r, 'non-canonical')],
  ['Number.isSafeInteger', Number, 'isSafeInteger', () => true,
    () => encode({ a: 2 ** 60 }), (r) => refusedWith(r, 'unsafe-integer')],
  ['Number.isInteger', Number, 'isInteger', () => true,
    () => encode({ a: 1.5 }), (r) => refusedWith(r, 'float')],
  ['Number.isFinite', Number, 'isFinite', () => true,
    () => encode({ a: NaN }), (r) => refusedWith(r, 'non-finite')],
  ['Object.is', Object, 'is', () => false,
    () => encode({ a: -0 }), (r) => refusedWith(r, 'negative-zero')],
  ['JSON.stringify', JSON, 'stringify', () => '"x"',
    () => encode({ a: 'hello' }), (r) => assert.equal(r.value, '{"a":"hello"}')],
  ['JSON.parse', JSON, 'parse', () => ({ a: 2 }),
    () => decode('{"a":1}').a, (r) => assert.equal(r.value, 1)],
  ['Object.getOwnPropertyNames', Object, 'getOwnPropertyNames', () => [],
    () => encode({ a: 1 }), (r) => assert.equal(r.value, '{"a":1}')],
  ['Object.keys', Object, 'keys', () => [],
    () => encode({ a: 1 }), (r) => assert.equal(r.value, '{"a":1}')],
  ['Reflect.ownKeys', Reflect, 'ownKeys', () => [],
    () => encode({ a: 1 }), (r) => assert.equal(r.value, '{"a":1}')],
  ['Object.getOwnPropertyDescriptor', Object, 'getOwnPropertyDescriptor', () => ({ value: 9, enumerable: true }),
    () => encode({ a: 1 }), (r) => assert.equal(r.value, '{"a":1}')],
  ['Object.hasOwn', Object, 'hasOwn', () => true,
    () => encode({ a: [1, , 2] }), (r) => refusedWith(r, 'array-shape')], // eslint-disable-line no-sparse-arrays
  ['Object.getPrototypeOf', Object, 'getPrototypeOf', () => Object.prototype,
    () => encode({ a: new Date(0) }), (r) => refusedWith(r, 'non-plain')],
  ['Reflect.getPrototypeOf', Reflect, 'getPrototypeOf', () => Object.prototype,
    () => encode({ a: new Date(0) }), (r) => refusedWith(r, 'non-plain')],
  ['Array.isArray', Array, 'isArray', () => false,
    () => encode({ a: [1] }), (r) => assert.equal(r.value, '{"a":[1]}')],
  ['Array.prototype.join', Array.prototype, 'join', () => 'x',
    () => encode({ a: [1, 2] }), (r) => assert.equal(r.value, '{"a":[1,2]}')],
  ['Array.prototype.push', Array.prototype, 'push', () => 0,
    () => encode({ a: [1, 2] }), (r) => assert.equal(r.value, '{"a":[1,2]}')],
  ['Array.prototype[Symbol.iterator]', Array.prototype, Symbol.iterator, function * () {},
    () => decode('{"a":[{"b":1}]}'), (r) => assert.ok(deepFrozen(r.value))], // checked after restoring
  ['Object.freeze', Object, 'freeze', (x) => x,
    () => decode('{"a":[{"b":1}]}'), (r) => assert.ok(deepFrozen(r.value))], // checked after restoring
  ['Object.values', Object, 'values', () => [],
    () => decode('{"a":[{"b":1}]}'), (r) => assert.ok(deepFrozen(r.value))], // checked after restoring
  ['String.prototype.charCodeAt', String.prototype, 'charCodeAt', () => 0,
    () => encode({ a: 'é'.repeat(32765) }), (r) => refusedWith(r, 'size')],
  ['Function.prototype.call', Function.prototype, 'call', () => undefined,
    () => encode({ b: [1], a: 'x' }), (r) => assert.equal(r.value, '{"a":"x","b":[1]}')],
  ['Function.prototype.apply', Function.prototype, 'apply', () => undefined,
    () => encode({ b: [1], a: 'x' }), (r) => assert.equal(r.value, '{"a":"x","b":[1]}')],
  ['Reflect.apply', Reflect, 'apply', () => undefined,
    () => encode({ b: [1], a: 'x' }), (r) => assert.equal(r.value, '{"a":"x","b":[1]}')],
  ['Map.prototype.has (a brand check)', Map.prototype, 'has', () => { throw new TypeError('x') },
    () => encode({ a: Object.setPrototypeOf(new Map(), Object.prototype) }), (r) => refusedWith(r, 'non-plain')],
]

test('patched built-in case count', () => {
  assert.equal(CASES.length, 29)
})

for (const [label, target, name, patch, run, check] of CASES) {
  test(`results are unchanged when ${label} is patched after loading`, () => check(underPatch(target, name, patch, run)))
}
