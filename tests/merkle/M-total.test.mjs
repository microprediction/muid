// Proofs come from whoever presents them: any input, of any type or size, is refused with false and never throws.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { merkle } from '../impl.mjs'

const { verifyInclusion, verifyConsistency, leafHash } = merkle
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 300)
const H = new Uint8Array(32)
const H1 = new Uint8Array(32).fill(1)
const is32 = (x) => x instanceof Uint8Array && x.length === 32

test('any input to either check returns false without throwing, unless it is a genuine proof', () => {
  fc.assert(fc.property(fc.anything({ withTypedArray: true, withBigInt: true, withNullPrototype: true }), (x) => {
    for (const r of [verifyInclusion(x), verifyConsistency(x)]) assert.equal(r, false)
    // Not a proof (the root is not the leaf hash), and no single replaced field makes it one, short of a hash.
    for (const field of ['leafHash', 'index', 'size', 'proof', 'root']) {
      if ((field === 'leafHash' || field === 'root') && is32(x)) continue
      assert.equal(verifyInclusion({ leafHash: H, index: 0, size: 1, proof: [], root: H1, [field]: x }), false, field)
    }
  }), { seed: SEED, numRuns: RUNS })
})

test('sizes are non-negative safe integers; hashes are 32-byte Uint8Arrays; proofs are arrays of at most 64', () => {
  const ok = { leafHash: H, index: 0, size: 1, proof: [], root: H }
  assert.equal(verifyInclusion(ok), true, 'a one-entry tree whose root is its leaf hash')
  for (const [name, over] of [['index = size', { index: 1 }], ['negative index', { index: -1 }], ['index 0.5', { index: 0.5 }],
    ['size 2^53', { size: 2 ** 53, index: 0 }], ['31-byte leaf', { leafHash: new Uint8Array(31) }], ['33-byte root', { root: new Uint8Array(33) }],
    ['a plain array as hash', { leafHash: Array.from(H) }], ['a proof of 65', { size: 2 ** 53 - 1, proof: Array.from({ length: 65 }, () => H) }],
    ['a proof element of 31 bytes', { size: 2, proof: [new Uint8Array(31)] }], ['a proof element of 33 bytes', { size: 2, proof: [new Uint8Array(33)] }],
    ['a proof element that is not bytes', { size: 2, proof: ['x'.repeat(32)] }], ['a proof that is not an array', { proof: { length: 0 } }]]) {
    assert.equal(verifyInclusion({ ...ok, ...over }), false, name)
  }
  assert.equal(verifyConsistency({ size1: 2, size2: 1, root1: H, root2: H, proof: [] }), false, 'size1 > size2')
  assert.equal(verifyConsistency({ size1: 1, size2: 1, root1: H, root2: H, proof: [H] }), false, 'equal sizes with a proof')
  assert.equal(verifyConsistency({ size1: 1, size2: 2, root1: H, root2: H, proof: [] }), false, 'an empty proof between different sizes')
})

test('a hostile object is refused, not thrown: a throwing getter, a throwing Proxy, a revoked Proxy', () => {
  const ok = { leafHash: H, index: 0, size: 1, proof: [], root: H }
  const getter = Object.defineProperty({ ...ok }, 'root', { get () { throw new Error('boom') } })
  const trap = new Proxy(ok, { get () { throw new Error('boom') } })
  const { proxy, revoke } = Proxy.revocable(ok, {}); revoke()
  const list = new Proxy([], { get (t, k) { if (k === 'length') return 1; throw new Error('boom') } })
  for (const x of [getter, trap, proxy, { ...ok, proof: list }]) {
    assert.equal(verifyInclusion(x), false)
    assert.equal(verifyConsistency(x), false)
  }
})

test('a proof longer than 64 is refused before any of its elements is read', () => {
  let reads = 0
  const huge = new Proxy([], { get (t, k) { if (k === 'length') return 1_000_000; reads++; return H } })
  assert.equal(verifyInclusion({ leafHash: H, index: 0, size: 2 ** 53 - 1, proof: huge, root: H }), false)
  assert.equal(reads, 0)
})

// Found by automated review: the length was read for the cap and read again as the loop bound, so a Proxy could
// pass the cap with one length and be copied with another.
test("a proof's length is read once: a length that grows after the cap is never enumerated", () => {
  for (const later of [65, 1_000_000_000]) {
    let lengths = 0
    let reads = 0
    const growing = new Proxy([], { get (t, k) { if (k === 'length') return lengths++ === 0 ? 0 : later; reads++; return H } })
    assert.equal(verifyInclusion({ leafHash: H, index: 0, size: 1, proof: growing, root: H }), true, 'the proof as first measured: empty')
    assert.deepEqual({ lengths, reads }, { lengths: 1, reads: 0 })
  }
  // And a length that is not a safe integer is refused before any element is read.
  for (const length of [-1, 1.5, NaN, '1', 2 ** 53]) {
    let reads = 0
    const odd = new Proxy([], { get (t, k) { if (k === 'length') return length; reads++; return H } })
    assert.equal(verifyInclusion({ leafHash: H, index: 0, size: 1, proof: odd, root: H }), false, String(length))
    assert.equal(reads, 0)
  }
})

test('leafHash takes a Uint8Array; anything else is a programming error', () => {
  for (const x of [undefined, 'ab', [1, 2], new Uint16Array(2)]) assert.throws(() => leafHash(x), /entry must be a Uint8Array/)
})
