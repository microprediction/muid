// E4: size and depth limits, enforced before work can grow past them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, decode, refuses, MAX_BYTES, MAX_DEPTH } from './helpers.mjs'

// Nested objects {"a":{"a":...{}}} of the given depth; the top-level object is depth 1.
function nested (depth) {
  let v = {}
  for (let i = 1; i < depth; i++) v = { a: v }
  return v
}

test('the limits are the values SPEC §3 states', () => {
  assert.equal(MAX_BYTES, 65536)
  assert.equal(MAX_DEPTH, 16)
})

test('depth 16 is accepted; depth 17 is refused', () => {
  assert.equal(encode(nested(16)), '{"a":'.repeat(15) + '{}' + '}'.repeat(15))
  refuses(() => encode(nested(17)), 'depth', 'depth 17')
})

test('arrays count towards depth', () => {
  let v = []
  for (let i = 2; i < 16; i++) v = [v]
  assert.doesNotThrow(() => encode({ a: v })) // object + 15 arrays = 16
  refuses(() => encode({ a: [v] }), 'depth', 'depth 17 through arrays')
})

test('very deep input is refused, not a stack overflow', () => {
  refuses(() => encode(nested(100000)), 'depth', 'depth 100000')
})

test('output of exactly MAX_BYTES is accepted; one byte more is refused', () => {
  // {"a":"…"} is 8 bytes plus the string.
  assert.equal(encode({ a: 'x'.repeat(65528) }).length, 65536)
  refuses(() => encode({ a: 'x'.repeat(65529) }), 'size', '65537 bytes')
})

test('size counts UTF-8 bytes, not UTF-16 code units', () => {
  // "é" is 2 bytes of UTF-8 and 1 code unit.
  assert.doesNotThrow(() => encode({ a: 'é'.repeat(32764) })) // 8 + 65528 = 65536 bytes
  refuses(() => encode({ a: 'é'.repeat(32765) }), 'size', '65538 bytes in 32773 code units')
})

test('a shared-object "diamond" is refused quickly instead of expanding', () => {
  let v = {}
  for (let i = 0; i < 15; i++) v = { a: v, b: v } // depth 16, 2^15 paths to the innermost object
  const start = performance.now()
  refuses(() => encode(v), 'size', 'diamond')
  assert.ok(performance.now() - start < 1000, 'refused in under a second')
})

test('decode refuses text over MAX_BYTES without calling JSON.parse', () => {
  const parse = JSON.parse
  let calls = 0
  JSON.parse = (...args) => { calls++; return parse(...args) }
  try {
    refuses(() => decode('{"a":"' + 'x'.repeat(65530) + '"}'), 'size', '65538 characters')
    refuses(() => decode('{"a":"' + 'é'.repeat(32765) + '"}'), 'size', '65538 bytes in 32773 code units')
  } finally {
    JSON.parse = parse
  }
  assert.equal(calls, 0)
})

test('decode accepts canonical text of exactly MAX_BYTES', () => {
  const text = '{"a":"' + 'x'.repeat(65528) + '"}'
  assert.equal(text.length, 65536)
  assert.equal(decode(text).a.length, 65528)
})

test('decode refuses depth 17', () => {
  refuses(() => decode('{"a":'.repeat(16) + '{}' + '}'.repeat(16)), 'depth', 'decoded depth 17')
})
