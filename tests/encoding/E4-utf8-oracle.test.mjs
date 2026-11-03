// E4: the size limit counts UTF-8 bytes exactly, checked against an independent count (Buffer.byteLength) at the
// boundary for every UTF-8 width and surrogate case. Characters are built from code points so no tool can rewrite them.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fc } from './arbitraries.mjs'
import { encode, decode, refuses, MAX_BYTES } from './helpers.mjs'

const cp = (...points) => String.fromCodePoint(...points)
const HIGH = String.fromCharCode(0xd800)
const LOW = String.fromCharCode(0xdfff)

// Characters at each UTF-8 width boundary, none of which JSON escapes.
const PROBES = [
  ['U+007F (1 byte)', cp(0x7f)], ['U+0080 (2 bytes)', cp(0x80)], ['U+07FF (2 bytes)', cp(0x7ff)],
  ['U+0800 (3 bytes)', cp(0x800)], ['U+D7FF (3 bytes)', cp(0xd7ff)], ['U+E000 (3 bytes)', cp(0xe000)],
  ['U+FFFF (3 bytes)', cp(0xffff)], ['U+10000 (4 bytes)', cp(0x10000)], ['U+10FFFF (4 bytes)', cp(0x10ffff)],
]

const bytes = (s) => Buffer.byteLength(s, 'utf8')

// '{"a":"' + filler + probe + tail + '"}', with the filler sized so the whole text is `target` bytes by the oracle.
function textOfSize (probe, tail, target) {
  const fixed = bytes('{"a":"' + probe + tail + '"}')
  const text = '{"a":"' + 'x'.repeat(target - fixed) + probe + tail + '"}'
  assert.equal(bytes(text), target)
  return text
}

for (const [label, ch] of PROBES) {
  for (const [where, tail] of [['last', ''], ['followed by x', 'x']]) {
    test(`encode: ${label}, ${where}: accepted at MAX_BYTES, refused one byte over`, () => {
      const at = JSON.parse(textOfSize(ch, tail, MAX_BYTES))
      const over = JSON.parse(textOfSize(ch, tail, MAX_BYTES + 1))
      assert.equal(bytes(encode(at)), MAX_BYTES)
      refuses(() => encode(over), 'size', label)
    })
    test(`decode: ${label}, ${where}: accepted at MAX_BYTES, refused one byte over`, () => {
      assert.ok(decode(textOfSize(ch, tail, MAX_BYTES)))
      refuses(() => decode(textOfSize(ch, tail, MAX_BYTES + 1)), 'size', label)
    })
  }
}

// Raw lone surrogates in decode input count as 3 bytes, as Buffer.byteLength counts them (U+FFFD). Within the limit
// the text is parsed and refused for the surrogate; one byte over, it is refused for size without being parsed.
const SURROGATE_CASES = [
  ['lone high', HIGH], ['lone low', LOW], ['high then high', HIGH + HIGH], ['low then high', LOW + HIGH],
  // Neighbours just outside the surrogate ranges, so each range bound is tested from both sides.
  ['low then low', LOW + LOW], ['U+E000 then lone low', cp(0xe000) + LOW], ['high then U+E000', HIGH + cp(0xe000)],
]
for (const [label, ch] of SURROGATE_CASES) {
  for (const [where, tail] of [['last', ''], ['followed by x', 'x']]) {
    test(`decode: ${label} surrogate, ${where}: counted as 3 bytes each`, () => {
      refuses(() => decode(textOfSize(ch, tail, MAX_BYTES)), 'surrogate', `${label} at the limit`)
      refuses(() => decode(textOfSize(ch, tail, MAX_BYTES + 1)), 'size', `${label} one over`)
    })
  }
}

test('decode: the extreme surrogate pair U+DBFF U+DC00 counts as 4 bytes', () => {
  const pair = String.fromCharCode(0xdbff, 0xdc00)
  assert.equal(bytes(pair), 4)
  assert.ok(decode(textOfSize(pair, '', MAX_BYTES)))
  refuses(() => decode(textOfSize(pair, '', MAX_BYTES + 1)), 'size', 'one over')
})

test('decode: a lone high surrogate as the very last character of the text', () => {
  // Not valid JSON, so within the limit it is a syntax error; one byte over, it is a size refusal.
  const body = '{"a":1}'
  const at = body + ' '.repeat(MAX_BYTES - bytes(body) - 3) + HIGH
  const over = body + ' '.repeat(MAX_BYTES - bytes(body) - 2) + HIGH
  assert.equal(bytes(at), MAX_BYTES)
  assert.equal(bytes(over), MAX_BYTES + 1)
  refuses(() => decode(at), 'syntax', 'at the limit')
  refuses(() => decode(over), 'size', 'one over')
})

test('property: near the limit, decode refuses for size exactly when the oracle says the text is too long', () => {
  const chars = fc.oneof(
    fc.constantFrom(...PROBES.map(([, c]) => c), HIGH, LOW, 'é', 'a'),
    fc.string({ unit: 'binary', maxLength: 3 }),
  )
  let over = 0; let within = 0
  fc.assert(fc.property(fc.array(chars, { maxLength: 6 }), fc.integer({ min: -6, max: 6 }), (parts, delta) => {
    const probe = parts.join('').replace(/["\\\u0000-\u001f]/g, 'x')
    const fixed = bytes('{"a":"' + probe + '"}')
    const target = MAX_BYTES + delta
    if (target - fixed < 0) return
    const text = '{"a":"' + 'x'.repeat(target - fixed) + probe + '"}'
    let reason = null
    try { decode(text) } catch (e) { reason = e.reason }
    if (bytes(text) > MAX_BYTES) { over++; assert.equal(reason, 'size') } else { within++; assert.notEqual(reason, 'size') }
  }))
  assert.ok(over > 0 && within > 0, `over ${over}, within ${within}`)
})
