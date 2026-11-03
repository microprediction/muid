// E3: every value outside the domain of SPEC §3 is refused, with its E5 reason. Hand-written cases.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, refuses } from './helpers.mjs'

const sym = Symbol('s')
class Thing { constructor () { this.a = 1 } }
class List extends Array {}

// [label, factory (a fresh value each time), reason]
const CASES = [
  // Keys
  ['__proto__ as an own key', () => JSON.parse('{"__proto__":1}'), 'key'],
  ['key toString', () => ({ toString: 1 }), 'key'],
  ['key hasOwnProperty', () => ({ hasOwnProperty: 1 }), 'key'],
  ['key "1"', () => ({ 1: 1 }), 'key'],
  ['key "10"', () => ({ 10: 1 }), 'key'],
  ['uppercase key', () => ({ A: 1 }), 'key'],
  ['empty key', () => ({ '': 1 }), 'key'],
  ['33-character key', () => ({ ['k' + 'x'.repeat(32)]: 1 }), 'key'],
  ['key with a lone surrogate', () => ({ ['a\ud800']: 1 }), 'key'],
  ['key with a hyphen', () => ({ 'a-b': 1 }), 'key'],
  ['key with a space', () => ({ 'a b': 1 }), 'key'],
  ['key with a non-ASCII letter', () => ({ 'é': 1 }), 'key'],
  ['key starting with a digit', () => ({ '1a': 1 }), 'key'],
  ['key starting with an underscore', () => ({ _a: 1 }), 'key'],
  ['symbol key', () => ({ [sym]: 1 }), 'symbol-key'],
  // Property descriptors
  ['getter', () => ({ a: Object.defineProperty({}, 'b', { get () { return 1 }, enumerable: true }) }), 'accessor'],
  ['setter only', () => ({ a: Object.defineProperty({}, 'b', { set (_) {}, enumerable: true }) }), 'accessor'],
  ['non-enumerable property', () => ({ a: Object.defineProperty({}, 'b', { value: 1, enumerable: false }) }), 'non-enumerable'],
  // Arrays
  ['hole', () => ({ a: [1, , 2] }), 'array-shape'], // eslint-disable-line no-sparse-arrays
  ['length beyond elements', () => { const a = []; a.length = 2; return { a } }, 'array-shape'],
  ['extra enumerable property on an array', () => { const a = [1]; a.x = 1; return { a } }, 'array-shape'],
  ['extra non-enumerable property on an array', () => { const a = [1]; Object.defineProperty(a, 'x', { value: 1 }); return { a } }, 'array-shape'],
  ['symbol property on an array', () => { const a = [1]; a[sym] = 1; return { a } }, 'array-shape'],
  // The own-key count matches (index 1, length, x), so only a per-index check finds the hole at 0.
  ['hole hidden by an extra property', () => { const a = [, 1]; a.x = 1; return { a } }, 'array-shape'], // eslint-disable-line no-sparse-arrays
  ['array subclass', () => ({ a: List.from([1]) }), 'non-plain'],
  ['undefined element', () => ({ a: [undefined] }), 'undefined'],
  // Numbers
  ['-0', () => ({ a: -0 }), 'negative-zero'],
  ['NaN', () => ({ a: NaN }), 'non-finite'],
  ['Infinity', () => ({ a: Infinity }), 'non-finite'],
  ['-Infinity', () => ({ a: -Infinity }), 'non-finite'],
  ['1.5', () => ({ a: 1.5 }), 'float'],
  ['0.1', () => ({ a: 0.1 }), 'float'],
  ['2^53', () => ({ a: 2 ** 53 }), 'unsafe-integer'],
  ['-(2^53)', () => ({ a: -(2 ** 53) }), 'unsafe-integer'],
  ['1e21', () => ({ a: 1e21 }), 'unsafe-integer'],
  // Other scalars
  ['null', () => ({ a: null }), 'null'],
  ['nested null', () => ({ a: { b: [null] } }), 'null'],
  ['undefined value', () => ({ a: undefined }), 'undefined'],
  ['BigInt', () => ({ a: 1n }), 'type'],
  ['function', () => ({ a: () => 1 }), 'type'],
  ['symbol value', () => ({ a: sym }), 'type'],
  // Non-plain objects
  ['Date', () => ({ a: new Date(0) }), 'non-plain'],
  ['Map', () => ({ a: new Map() }), 'non-plain'],
  ['Set', () => ({ a: new Set() }), 'non-plain'],
  ['RegExp', () => ({ a: /x/ }), 'non-plain'],
  ['Uint8Array', () => ({ a: new Uint8Array(1) }), 'non-plain'],
  ['ArrayBuffer', () => ({ a: new ArrayBuffer(1) }), 'non-plain'],
  ['class instance', () => ({ a: new Thing() }), 'non-plain'],
  ['boxed number', () => ({ a: Object(1) }), 'non-plain'],
  ['boxed string', () => ({ a: Object('x') }), 'non-plain'],
  ['boxed boolean', () => ({ a: Object(true) }), 'non-plain'],
  ['Error', () => ({ a: new Error('x') }), 'non-plain'],
  ['object with an inherited prototype', () => ({ a: Object.create({ x: 1 }) }), 'non-plain'],
  // Cycles
  ['object containing itself', () => { const o = {}; o.a = o; return o }, 'cycle'],
  ['array containing itself', () => { const a = []; a.push(a); return { a } }, 'cycle'],
  ['cycle through two objects', () => { const o = { a: {} }; o.a.b = o; return o }, 'cycle'],
  // Strings
  ['lone high surrogate', () => ({ a: 'x\ud800' }), 'surrogate'],
  ['lone low surrogate', () => ({ a: '\udc00x' }), 'surrogate'],
  ['surrogates in the wrong order', () => ({ a: '\udc00\ud800' }), 'surrogate'],
  // Top level
  ['top-level array', () => [], 'top-level'],
  ['top-level string', () => 'x', 'top-level'],
  ['top-level number', () => 1, 'top-level'],
  ['top-level boolean', () => true, 'top-level'],
  ['top-level null', () => null, 'top-level'],
  ['top-level undefined', () => undefined, 'top-level'],
  ['top-level Date', () => new Date(0), 'top-level'],
  ['top-level class instance', () => new Thing(), 'top-level'],
]

test('value refusal count', () => {
  assert.equal(CASES.length, 67)
})

for (const [label, make, reason] of CASES) {
  test(`encode refuses: ${label}`, () => refuses(() => encode(make()), reason, label))
}

test('a getter is never invoked, even while refusing it', () => {
  let calls = 0
  const o = { a: Object.defineProperty({}, 'b', { get () { calls++; return 1 }, enumerable: true }) }
  refuses(() => encode(o), 'accessor', 'getter')
  assert.equal(calls, 0)
})
