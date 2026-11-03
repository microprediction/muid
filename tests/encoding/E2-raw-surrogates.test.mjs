// E2 + E4: decode input containing raw (unescaped) lone surrogates. Built from code points so no tool can rewrite them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decode, refuses } from './helpers.mjs'

const HIGH = String.fromCharCode(0xd800)
const LOW = String.fromCharCode(0xdc00)

test('a raw lone high surrogate inside a string is refused', () => {
  refuses(() => decode(`{"a":"${HIGH}"}`), 'surrogate', 'raw high')
})

test('a raw lone low surrogate inside a string is refused', () => {
  refuses(() => decode(`{"a":"${LOW}"}`), 'surrogate', 'raw low')
})

test('a raw high surrogate followed by an ASCII character is refused', () => {
  refuses(() => decode(`{"a":"${HIGH}x"}`), 'surrogate', 'high then ASCII')
})

test('a raw surrogate pair is an ordinary character', () => {
  assert.equal(decode(`{"a":"${HIGH}${LOW}"}`).a, HIGH + LOW)
})

test('text ending in a raw lone high surrogate is a syntax error', () => {
  refuses(() => decode(`{"a":1}${HIGH}`), 'syntax', 'trailing high')
})

test('a lone surrogate counts as 3 bytes towards MAX_BYTES', () => {
  // {"a":"…"} is 8 bytes plus the string; 21843 lone surrogates at 3 bytes each make 65537.
  refuses(() => decode(`{"a":"${HIGH.repeat(21843)}"}`), 'size', '65537 bytes')
  // One fewer fits the limit, so it is parsed and refused for the surrogate instead.
  refuses(() => decode(`{"a":"${HIGH.repeat(21842)}"}`), 'surrogate', '65534 bytes')
})
