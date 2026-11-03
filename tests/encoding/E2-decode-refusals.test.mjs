// E2: decode accepts only text that is exactly the canonical encoding of its value. Hand-written cases.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decode, refuses } from './helpers.mjs'

// A backslash built from its code point, so no tool or editor can turn a typed "é" into a literal "é" (which
// happened once, silently making three of these cases canonical). The guard test at the bottom pins the bytes.
const BS = String.fromCharCode(92)
const ESCAPED_E_ACUTE = `{"a":"${BS}u00e9"}`
const ESCAPED_A = `{"a":"${BS}u0041"}`
const ESCAPED_KEY = `{"${BS}u0061":1}`

const CASES = [
  // Parses, but is not canonical.
  ['leading space', ' {}', 'non-canonical'],
  ['trailing newline', '{}\n', 'non-canonical'],
  ['space after colon', '{"a": 1}', 'non-canonical'],
  ['space after comma', '{"a":1, "b":2}', 'non-canonical'],
  ['duplicate key, last wins in JSON.parse', '{"a":1,"a":2}', 'non-canonical'],
  ['duplicate key, same value', '{"a":1,"a":1}', 'non-canonical'],
  ['keys out of order', '{"b":1,"a":2}', 'non-canonical'],
  ['escaped slash', String.raw`{"a":"\/"}`, 'non-canonical'],
  ['escaped e-acute', ESCAPED_E_ACUTE, 'non-canonical'],
  ['escaped ASCII letter', ESCAPED_A, 'non-canonical'],
  ['uppercase hex in escape', String.raw`{"a":"\u001F"}`, 'non-canonical'],
  ['escaped DEL', String.raw`{"a":"\u007f"}`, 'non-canonical'],
  ['\\u000a instead of \\n', String.raw`{"a":"\u000a"}`, 'non-canonical'],
  ['escaped key', ESCAPED_KEY, 'non-canonical'],
  ['exponent form of an integer', '{"a":1e0}', 'non-canonical'],
  ['trailing .0', '{"a":1.0}', 'non-canonical'],
  // Parses to a value outside the domain.
  ['minus zero', '{"a":-0}', 'negative-zero'],
  ['fraction', '{"a":1.5}', 'float'],
  ['exponent overflow', '{"a":1e400}', 'non-finite'],
  ['null', '{"a":null}', 'null'],
  ['top-level array', '[]', 'top-level'],
  ['top-level string', '"x"', 'top-level'],
  ['top-level number', '1', 'top-level'],
  ['top-level null', 'null', 'top-level'],
  ['uppercase key', '{"A":1}', 'key'],
  ['__proto__ key', '{"__proto__":1}', 'key'],
  ['numeric key', '{"1":1}', 'key'],
  ['lone surrogate escape', String.raw`{"a":"\ud800"}`, 'surrogate'],
  ['2^53', '{"a":9007199254740992}', 'unsafe-integer'],
  ['twenty-digit integer', '{"a":12345678901234567890}', 'unsafe-integer'],
  // Does not parse.
  ['leading zero', '{"a":01}', 'syntax'],
  ['empty text', '', 'syntax'],
  ['unclosed object', '{', 'syntax'],
  ['trailing comma', '{"a":1,}', 'syntax'],
  ['two documents', '{}{}', 'syntax'],
  ['bad literal', '{"a":tru}', 'syntax'],
  ['single quotes', "{'a':1}", 'syntax'],
  ['raw control character in a string', '{"a":"\u0001"}', 'syntax'],
  ['byte-order mark before the object', '﻿{}', 'syntax'],
]

test('decode refusal count', () => {
  assert.equal(CASES.length, 39)
})

for (const [label, text, reason] of CASES) {
  test(`decode refuses: ${label}`, () => refuses(() => decode(text), reason, label))
}

test('decode refuses a non-string input with "type"', () => {
  for (const input of [undefined, null, 1, {}, [], new Uint8Array([123, 125]), Buffer.from('{}')]) {
    refuses(() => decode(input), 'type', `input ${Object.prototype.toString.call(input)}`)
  }
})

test('the escaped cases contain a real backslash escape', () => {
  assert.deepEqual([...ESCAPED_E_ACUTE].map((c) => c.charCodeAt(0)),
    [123, 34, 97, 34, 58, 34, 92, 117, 48, 48, 101, 57, 34, 125])
  assert.equal(ESCAPED_A.length, 14)
  assert.equal(ESCAPED_KEY.length, 12)
  assert.ok(ESCAPED_A.includes(BS + 'u0041') && ESCAPED_KEY.includes(BS + 'u0061'))
})
