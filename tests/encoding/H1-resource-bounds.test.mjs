// E4: work and memory are bounded by MAX_BYTES, whatever the size of the value handed to encode. Found by adversarial
// review: a huge string was copied and escaped in full before the size check (and could throw RangeError), and a
// wide array or object was enumerated in full before any check.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, refuses } from './helpers.mjs'
import { execFileSync } from 'node:child_process'

const NUL = String.fromCharCode(0)

function quickly (ms, fn) {
  const t0 = performance.now()
  fn()
  const took = performance.now() - t0
  assert.ok(took < ms, `took ${Math.round(took)} ms`)
}

// Refused from its length alone: scanning it, even without copying, takes hundreds of milliseconds.
test('a 100-million-character string is refused for size without being copied or scanned', () => {
  const s = 'x'.repeat(1e8)
  quickly(100, () => refuses(() => encode({ a: s }), 'size', '1e8 characters'))
})

test('a string whose escaped form would exceed the engine string limit is refused for size, not RangeError', () => {
  const s = NUL.repeat(1e8) // each NUL escapes to 6 characters: 6e8 is past V8's maximum string length
  quickly(100, () => refuses(() => encode({ a: s }), 'size', 'NUL x 1e8'))
})

test('the string pre-check counts the bytes already written', () => {
  // {"a":"<30000>","b":"<n>"} is 2 + 6 + 30000 + 1 + 6 + n = 30015 + n bytes.
  assert.equal(encode({ a: 'x'.repeat(30000), b: 'y'.repeat(35521) }).length, 65536)
  refuses(() => encode({ a: 'x'.repeat(30000), b: 'y'.repeat(35522) }), 'size', 'one over')
})

// An array of length L needs at least 2L + 1 bytes and is followed by at least one more; an object with k keys needs
// at least 6k + 1. A container that cannot fit is refused on entry, before its members are looked at (E5 order:
// cycle, depth, plainness, width, shape).
test('array width: refused on entry exactly when bytes written + 2L + 2 > MAX_BYTES', () => {
  // Under {"a": … the bytes already written are 5, so the array passes the width check exactly when L <= 32764.
  const fits = new Array(32764).fill(0); fits[0] = null
  const wide = new Array(32765).fill(0); wide[0] = null
  refuses(() => encode({ a: fits }), 'null', 'L = 32764 passes the width check, then meets null')
  refuses(() => encode({ a: wide }), 'size', 'L = 32765 is refused on entry')
})

test('array width bound is exact: an array that fits to the last byte is accepted', () => {
  // {"ab":[0,…]} is 6 + (2L + 1) + 1 bytes: L = 32764 gives exactly 65536, and the bound equals the limit.
  assert.equal(encode({ ab: new Array(32764).fill(0) }).length, 65536)
  refuses(() => encode({ ab: new Array(32765).fill(0) }), 'size', 'one element over')
})

test('array boundary inside an object: {"a":[0,…]} is 2L + 7 bytes', () => {
  assert.equal(encode({ a: new Array(32764).fill(0) }).length, 65535)
  refuses(() => encode({ a: new Array(32765).fill(0) }), 'size', '65537 bytes')
})

test('object width: refused on entry exactly when 6k + 1 > MAX_BYTES', () => {
  const make = (k) => {
    const o = { A: 1 } // an invalid key that sorts first
    for (let i = 1; i < k; i++) o['k' + i] = 0
    assert.equal(Object.keys(o).length, k)
    return o
  }
  refuses(() => encode(make(10922)), 'key', 'k = 10922 passes the width check, then meets "A"')
  refuses(() => encode(make(10923)), 'size', 'k = 10923 is refused on entry')
})

test('a sparse array of length 2^32 - 1 is refused for size at once', () => {
  const a = []; a.length = 2 ** 32 - 1
  quickly(100, () => refuses(() => encode({ a }), 'size', 'length 2^32 - 1'))
})

test('a dense array of 2 million elements is refused for size without enumerating it', () => {
  const a = new Array(2e6).fill(0)
  quickly(200, () => refuses(() => encode({ a }), 'size', '2e6 elements'))
})

// A string's JSON text is measured, escapes included, before it is built: a control character escapes to six bytes,
// so a string of a few thousand of them was copied and escaped past the limit before being refused. Found by
// automated review. A child process patches JSON.stringify to count calls before loading the encoder (which captures
// it, E7), so the counts show the copy is never made. It runs with this process's arguments and environment (a mutation
// tester's hooks included), but without coverage, which the same cases give here.
const CHILD = `
const stringify = JSON.stringify
let calls = 0
JSON.stringify = function (...args) { calls++; return Reflect.apply(stringify, this, args) }
const { encoding } = await import(${JSON.stringify(new URL('../impl.mjs', import.meta.url).href)})
const out = []
for (const [ch, width] of JSON.parse(process.argv[1])) {
  const n = Math.floor(65528 / width)
  const fits = ch.repeat(n) + 'x'.repeat(65528 - n * width)
  calls = 0
  const text = encoding.encode({ a: fits })
  const fitCalls = calls
  calls = 0
  let reason
  try { encoding.encode({ a: fits + 'x' }) } catch (e) { reason = e instanceof encoding.EncodingError ? e.reason : String(e) }
  out.push({ same: text === stringify({ a: fits }), bytes: Buffer.byteLength(text), fitCalls, reason, overCalls: calls })
}
process.stdout.write(stringify(out))
`

test('a string is measured with its escapes before it is copied: one that cannot fit never reaches JSON.stringify', () => {
  // {"a":"…"} puts 8 bytes around the string, so it fits exactly when its escaped UTF-8 is 65528 bytes.
  const WIDTHS = [[NUL, 6], ['\x07', 6], ['\b', 2], ['\t', 2], ['\n', 2], ['\v', 6], ['\f', 2], ['\r', 2], ['\x0e', 6],
    ['\x1f', 6], ['"', 2], ['\\', 2], [' ', 1], ['!', 1], ['\x7f', 1], ['\x80', 2], ['\u07ff', 2], ['\u0800', 3], ['\u{1f600}', 4]]
  const { NODE_TEST_CONTEXT, NODE_V8_COVERAGE, ...env } = process.env // coverage is this process's, below
  const results = JSON.parse(execFileSync(process.execPath, [...process.execArgv, '--input-type=module', '-e', CHILD, JSON.stringify(WIDTHS)],
    { env, encoding: 'utf8' }))
  assert.equal(results.length, WIDTHS.length)
  WIDTHS.forEach(([ch, width], i) => {
    const label = `U+${ch.codePointAt(0).toString(16)}`
    assert.deepEqual(results[i], { same: true, bytes: 65536, fitCalls: 1, reason: 'size', overCalls: 0 }, label)
    // The measured size is the one counted, so the same holds in this process without the counting.
    const n = Math.floor(65528 / width)
    const fits = ch.repeat(n) + 'x'.repeat(65528 - n * width)
    assert.equal(encode({ a: fits }), JSON.stringify({ a: fits }), label)
    refuses(() => encode({ a: fits + 'x' }), 'size', `${label}: one byte over`)
  })
})
