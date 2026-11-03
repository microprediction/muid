// E3, E6: a Proxy cannot be detected in a browser, so the encoder makes one harmless instead. Every property is read
// exactly once, a container's length is read once, and anything foreign a trap throws becomes EncodingError('exotic').
// A Proxy can still choose what is encoded — as any caller can, by building the object — and the bytes are what get
// signed. Found by adversarial review.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encode, EncodingError, REASONS, refuses } from './helpers.mjs'

function outcome (fn) {
  const t0 = performance.now()
  try {
    return { value: fn(), ms: performance.now() - t0 }
  } catch (e) {
    return { error: e, ms: performance.now() - t0 }
  }
}

test('a trap that throws an Error is refused as exotic', () => {
  const p = new Proxy({}, { ownKeys () { throw new Error('boom') } })
  refuses(() => encode({ a: p }), 'exotic', 'ownKeys throws')
})

test('a trap that throws a non-Error value is refused as exotic', () => {
  const p = new Proxy({}, { ownKeys () { throw 42 } }) // eslint-disable-line no-throw-literal
  refuses(() => encode({ a: p }), 'exotic', 'ownKeys throws 42')
})

test('a getPrototypeOf trap that throws is refused as exotic', () => {
  const p = new Proxy({}, { getPrototypeOf () { throw new Error('no') } })
  refuses(() => encode({ a: p }), 'exotic', 'getPrototypeOf throws')
  refuses(() => encode(p), 'exotic', 'top-level getPrototypeOf throws')
})

test('a revoked proxy is refused as exotic, nested or at the top level', () => {
  const nested = Proxy.revocable({}, {}); nested.revoke()
  const top = Proxy.revocable({}, {}); top.revoke()
  refuses(() => encode({ a: nested.proxy }), 'exotic', 'nested revoked')
  refuses(() => encode(top.proxy), 'exotic', 'top-level revoked')
})

test('a key the proxy lists but has no descriptor for is refused as exotic', () => {
  const p = new Proxy({}, { ownKeys: () => ['z'], getOwnPropertyDescriptor: () => undefined })
  refuses(() => encode({ a: p }), 'exotic', 'missing descriptor')
})

test('an ownKeys result that breaks a Proxy invariant is refused as exotic', () => {
  const p = new Proxy({}, { ownKeys: () => ['a', 'a'] })
  refuses(() => encode({ a: p }), 'exotic', 'duplicate keys from ownKeys')
})

test('a nested proxy that deletes a key of its parent mid-encoding yields an EncodingError, nothing else', () => {
  const parent = { a: null, b: 1 }
  parent.a = new Proxy({}, { ownKeys () { delete parent.b; return [] } })
  const r = outcome(() => encode(parent))
  if (r.error) assert.ok(r.error instanceof EncodingError && REASONS.includes(r.error.reason), String(r.error))
})

test('an array proxy whose length changes between reads cannot loop: length is read once', () => {
  let reads = 0
  const p = new Proxy([], { get (t, k) { if (k === 'length') return reads++ === 0 ? 0 : Infinity; return Reflect.get(t, k) } })
  const r = outcome(() => encode({ a: p }))
  assert.ok(r.ms < 1000, `took ${Math.round(r.ms)} ms`)
  assert.ok(reads <= 1, `length read ${reads} times`)
  if (r.error) assert.ok(r.error instanceof EncodingError, String(r.error))
})

test('every trap runs at most once per object and per property (read once)', () => {
  const counts = new Map()
  const count = (path, trap, key) => {
    const k = `${path} ${trap} ${String(key)}`
    counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  const watch = (target, path) => new Proxy(target, {
    getPrototypeOf (t) { count(path, 'getPrototypeOf', ''); return Reflect.getPrototypeOf(t) },
    ownKeys (t) { count(path, 'ownKeys', ''); return Reflect.ownKeys(t) },
    getOwnPropertyDescriptor (t, k) { count(path, 'getOwnPropertyDescriptor', k); return Reflect.getOwnPropertyDescriptor(t, k) },
    get (t, k) { count(path, 'get', k); return Reflect.get(t, k) },
    has (t, k) { count(path, 'has', k); return Reflect.has(t, k) },
  })
  const value = watch({ b: watch([1, watch({ d: 2 }, 'b[1]')], 'b'), a: 'x' }, 'root')
  assert.equal(encode(value), '{"a":"x","b":[1,{"d":2}]}')
  const repeated = [...counts].filter(([, n]) => n > 1)
  assert.deepEqual(repeated, [])
  assert.ok(counts.size >= 8, `traps observed: ${counts.size}`)
})

test('a proxy that behaves like a plain object encodes like one', () => {
  assert.equal(encode(new Proxy({ b: 1, a: [true] }, {})), '{"a":[true],"b":1}')
})
