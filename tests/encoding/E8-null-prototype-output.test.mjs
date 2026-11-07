// E8: decoded objects and arrays have null prototypes, so prototype pollution elsewhere in the page can never make an
// absent field read as present. Found by adversarial review.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, decode } from './helpers.mjs'

const TEXT = '{"a":{"b":1},"c":[{"d":2},[3]]}'

function containers (v, out = []) {
  if (typeof v === 'object' && v !== null) {
    out.push(v)
    for (const k of Object.keys(v)) containers(v[k], out)
  }
  return out
}

test('every decoded object and array has a null prototype', () => {
  const all = containers(decode(TEXT))
  assert.equal(all.length, 5) // the root, a, c, c[0] and c[1]
  for (const c of all) assert.equal(Object.getPrototypeOf(c), null)
  assert.ok(Array.isArray(decode(TEXT).c), 'arrays are still arrays')
})

test('Object.prototype pollution does not reach decoded objects', () => {
  Object.prototype.admin = true // eslint-disable-line no-extend-native
  let v
  try {
    v = decode(TEXT)
  } finally {
    delete Object.prototype.admin
  }
  assert.equal(v.admin, undefined)
  assert.equal(v.a.admin, undefined)
  assert.equal('admin' in v, false)
  assert.equal(v.constructor, undefined)
})

test('Array.prototype pollution does not reach decoded arrays', () => {
  Array.prototype[5] = 'x' // eslint-disable-line no-extend-native
  let v
  try {
    v = decode(TEXT)
  } finally {
    delete Array.prototype[5]
  }
  assert.equal(v.c[5], undefined)
  assert.equal(v.c.length, 2)
})

test('decoded values re-encode to the same text (null-prototype arrays are in the domain)', () => {
  assert.equal(encode(decode(TEXT)), TEXT)
})

// The copy is written by assignment into objects that already have null prototypes: setters planted on
// Object.prototype for its keys, or on Array.prototype for its indices, are never reached.
test('decoding meets no setter planted on Object.prototype or on Array.prototype\'s indices', () => {
  let called = 0
  const planted = [[Object.prototype, 'a'], [Object.prototype, 'b']]
  for (const [o, k] of planted) Object.defineProperty(o, k, { configurable: true, set () { called++ }, get () { return 'planted' } })
  try {
    const v = decode('{"a":[["x","y"],{"a":2}],"b":1}')
    assert.equal(called, 0)
    assert.deepEqual(Object.keys(v), ['a', 'b'])
    assert.equal(v.a[0][1], 'y')
    assert.equal(v.a[1].a, 2)
    assert.equal(v.b, 1)
    assert.equal(Object.getPrototypeOf(v.a), null)
    assert.equal(Object.getOwnPropertyDescriptor(v.a, '0').writable, false)
  } finally {
    for (const [o, k] of planted) delete o[k]
  }
  Object.defineProperty(Array.prototype, '1', { configurable: true, set () { called++ }, get () { return 'planted' } }) // eslint-disable-line no-extend-native
  try {
    assert.equal(decode('{"a":["x","y"]}').a[1], 'y')
    assert.equal(called, 0)
  } finally {
    delete Array.prototype[1]
  }
})
