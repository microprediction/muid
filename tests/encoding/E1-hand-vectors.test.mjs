// E1: hand-written known answers. Every expected string below was typed by hand, never computed by an encoder.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, decode, plain } from './helpers.mjs'

const K32 = 'k' + 'x'.repeat(31)
const shared = { x: 1 }

// [label, value, expected text, encodeOnly]
const CASES = [
  ['empty object', {}, '{}'],
  ['one member', { a: 1 }, '{"a":1}'],
  ['keys sorted', { b: 1, a: 2 }, '{"a":2,"b":1}'],
  ['empty array', { a: [] }, '{"a":[]}'],
  ['nested empty object', { a: {} }, '{"a":{}}'],
  ['booleans', { t: true, f: false }, '{"f":false,"t":true}'],
  ['negative integer', { a: -1 }, '{"a":-1}'],
  ['zero', { a: 0 }, '{"a":0}'],
  ['largest safe integer', { a: 9007199254740991 }, '{"a":9007199254740991}'],
  ['smallest safe integer', { a: -9007199254740991 }, '{"a":-9007199254740991}'],
  ['empty string', { a: '' }, '{"a":""}'],
  ['NUL escaped as lowercase \\u', { a: '\u0000' }, '{"a":"\\u0000"}'],
  ['U+001F escaped as lowercase \\u', { a: '\u001f' }, '{"a":"\\u001f"}'],
  ['U+000F escaped as lowercase \\u', { a: '\u000f' }, '{"a":"\\u000f"}'],
  ['short escapes', { a: '\b\f\n\r\t' }, '{"a":"\\b\\f\\n\\r\\t"}'],
  ['quote and backslash', { a: '"\\' }, '{"a":"\\"\\\\"}'],
  ['slash is not escaped', { a: '/' }, '{"a":"/"}'],
  ['DEL is literal', { a: '\u007f' }, '{"a":"\u007f"}'],
  ['U+0080 is literal', { a: '\u0080' }, '{"a":"\u0080"}'],
  ['U+2028 and U+2029 are literal', { a: '  ' }, '{"a":"  "}'],
  ['U+FEFF inside a string is literal', { a: '﻿' }, '{"a":"﻿"}'],
  ['astral character is literal', { a: '\u{1F600}' }, '{"a":"\u{1F600}"}'],
  ['e-acute is literal', { a: 'é' }, '{"a":"é"}'],
  ['script tag is not escaped', { a: '</script>' }, '{"a":"</script>"}'],
  ['sorting at every level', { b: { d: 1, c: 2 }, a: [{ z: 1, y: 2 }] }, '{"a":[{"y":2,"z":1}],"b":{"c":2,"d":1}}'],
  ['ASCII key order: a < a0 < a_ < aa', { a_: 1, a0: 2, a: 3, aa: 4 }, '{"a":3,"a0":2,"a_":1,"aa":4}'],
  ['key "constructor" is an ordinary key', { constructor: 1 }, '{"constructor":1}'],
  ['key "valueof" is an ordinary key', { valueof: 2 }, '{"valueof":2}'],
  ['key "length" in an object is an ordinary key', { length: 1 }, '{"length":1}'],
  ['key "length" holding an array', { a: { length: [3, 4] } }, '{"a":{"length":[3,4]}}'],
  ['32-character key', { [K32]: 1 }, '{"' + K32 + '":1}'],
  ['digits and underscore in a key', { a1_b2: 1 }, '{"a1_b2":1}'],
  ['nested arrays', { a: [1, [2, [3]]] }, '{"a":[1,[2,[3]]]}'],
  ['array order is kept', { a: [3, 1, 2] }, '{"a":[3,1,2]}'],
  ['shared object encodes as its expansion', { a: shared, b: shared }, '{"a":{"x":1},"b":{"x":1}}'],
  ['frozen input', Object.freeze({ a: Object.freeze([1]) }), '{"a":[1]}'],
  ['null-prototype object', Object.assign(Object.create(null), { b: 1, a: 2 }), '{"a":2,"b":1}', true],
]

test('hand-written vector count', () => {
  assert.equal(CASES.length, 37)
})

for (const [label, value, expected, encodeOnly] of CASES) {
  test(`encode: ${label}`, () => {
    assert.equal(encode(value), expected)
  })
  if (!encodeOnly) {
    test(`decode: ${label}`, () => {
      assert.deepStrictEqual(plain(decode(expected)), value)
    })
  }
}
