// E4: work and memory are bounded by MAX_BYTES, whatever the size of the value handed to encode. Found by adversarial
// review: a huge string was copied and escaped in full before the size check (and could throw RangeError), and a
// wide array or object was enumerated in full before any check.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, refuses } from './helpers.mjs'

const NUL = String.fromCharCode(0)

function quickly (ms, fn) {
  const t0 = performance.now()
  fn()
  const took = performance.now() - t0
  assert.ok(took < ms, `took ${Math.round(took)} ms`)
}

test('a 100-million-character string is refused for size without being copied', () => {
  const s = 'x'.repeat(1e8)
  quickly(1000, () => refuses(() => encode({ a: s }), 'size', '1e8 characters'))
})

test('a string whose escaped form would exceed the engine string limit is refused for size, not RangeError', () => {
  const s = NUL.repeat(1e8) // each NUL escapes to 6 characters: 6e8 is past V8's maximum string length
  quickly(1000, () => refuses(() => encode({ a: s }), 'size', 'NUL x 1e8'))
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
