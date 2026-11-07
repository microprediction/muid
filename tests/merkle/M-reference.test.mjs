// RFC 9162 §2.1: an independent reference (MTH, PATH and PROOF, computed by the recursions in §2.1.1, §2.1.3.1 and
// §2.1.4.1) builds random trees and their proofs; the verifier accepts every genuine proof and refuses each one changed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fc from 'fast-check'
import { merkle } from '../impl.mjs'
import { runs } from '../runs.mjs'

const { verifyInclusion, verifyConsistency, leafHash } = merkle
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = runs(200)

const sha = (...parts) => new Uint8Array(createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest())
const LEAF = (d) => sha([0x00], d)
const NODE = (l, r) => sha([0x01], l, r)
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k } // the largest power of two below n
// §2.1.1: MTH(D[n]).
function mth (d) {
  if (d.length === 0) return sha()
  if (d.length === 1) return LEAF(d[0])
  const k = split(d.length)
  return NODE(mth(d.slice(0, k)), mth(d.slice(k)))
}
// §2.1.3.1: PATH(m, D[n]).
function path (m, d) {
  if (d.length <= 1) return []
  const k = split(d.length)
  return m < k ? [...path(m, d.slice(0, k)), mth(d.slice(k))] : [...path(m - k, d.slice(k)), mth(d.slice(0, k))]
}
// §2.1.4.1: SUBPROOF(m, D[n], b) and PROOF(m, D[n]).
function subproof (m, d, b) {
  if (m === d.length) return b ? [] : [mth(d)]
  const k = split(d.length)
  return m <= k ? [...subproof(m, d.slice(0, k), b), mth(d.slice(k))] : [...subproof(m - k, d.slice(k), false), mth(d.slice(0, k))]
}
const consistencyProof = (m, d) => subproof(m, d, true)

const tree = fc.integer({ min: 1, max: 70 }).chain((n) => fc.tuple(fc.constant(n), fc.array(fc.uint8Array({ maxLength: 8 }), { minLength: n, maxLength: n })))
const flip = (list, i, bit) => list.map((h, j) => (j === i ? Uint8Array.from(h, (b, k) => (k === bit >> 3 ? b ^ (1 << (bit & 7)) : b)) : h))

test('leafHash is SHA-256 of 0x00 and the entry', () => {
  for (const e of [new Uint8Array(0), Uint8Array.from([1, 2, 3])]) assert.deepEqual(leafHash(e), LEAF(e))
})

test('inclusion: every genuine proof verifies; a changed proof, index, size, leaf or root does not', () => {
  fc.assert(fc.property(tree, fc.nat(), fc.nat(), ([n, d], at, bit) => {
    const m = at % n
    const p = path(m, d)
    const root = mth(d)
    const args = { leafHash: LEAF(d[m]), index: m, size: n, proof: p, root }
    assert.equal(verifyInclusion(args), true)
    if (p.length > 0) assert.equal(verifyInclusion({ ...args, proof: flip(p, bit % p.length, bit % 256) }), false, 'a flipped bit')
    if (p.length > 0) assert.equal(verifyInclusion({ ...args, proof: p.slice(1) }), false, 'a shorter proof')
    assert.equal(verifyInclusion({ ...args, proof: [...p, root] }), false, 'a longer proof')
    assert.equal(verifyInclusion({ ...args, leafHash: LEAF(Uint8Array.from([...d[m], 0])) }), false, 'another leaf')
    assert.equal(verifyInclusion({ ...args, root: flip([root], 0, bit % 256)[0] }), false, 'another root')
    const distinct = new Set(d.map((x) => Buffer.from(x).toString('hex'))).size === n
    if (n > 1 && distinct) assert.equal(verifyInclusion({ ...args, index: (m + 1) % n }), false, 'another index')
  }), { seed: SEED, numRuns: RUNS })
})

test('consistency: every genuine proof verifies; a changed proof, size or root does not', () => {
  fc.assert(fc.property(tree, fc.nat(), fc.nat(), ([n, d], at, bit) => {
    const m = 1 + (at % n) // 1 ≤ m ≤ n
    const p = consistencyProof(m, d)
    const args = { size1: m, size2: n, root1: mth(d.slice(0, m)), root2: mth(d), proof: p }
    assert.equal(verifyConsistency(args), true, `m ${m}, n ${n}`)
    if (p.length > 0) assert.equal(verifyConsistency({ ...args, proof: flip(p, bit % p.length, bit % 256) }), false, 'a flipped bit')
    if (p.length > 0) assert.equal(verifyConsistency({ ...args, proof: p.slice(0, -1) }), false, 'a shorter proof')
    assert.equal(verifyConsistency({ ...args, proof: [...p, args.root2] }), false, 'a longer proof')
    assert.equal(verifyConsistency({ ...args, root1: flip([args.root1], 0, bit % 256)[0] }), false, 'another first root')
    assert.equal(verifyConsistency({ ...args, root2: flip([args.root2], 0, bit % 256)[0] }), false, 'another second root')
    if (m < n) assert.equal(verifyConsistency({ ...args, size1: n, size2: m }), false, 'sizes swapped')
  }), { seed: SEED, numRuns: RUNS })
})

test('the empty tree: consistent with any tree by an empty proof, and its root is SHA-256 of nothing', () => {
  const d = [Uint8Array.from([1]), Uint8Array.from([2])]
  assert.equal(verifyConsistency({ size1: 0, size2: 2, root1: sha(), root2: mth(d), proof: [] }), true)
  assert.equal(verifyConsistency({ size1: 0, size2: 2, root1: mth(d), root2: mth(d), proof: [] }), false, 'a size-0 tree with another root')
  assert.equal(verifyConsistency({ size1: 0, size2: 0, root1: sha(), root2: sha(), proof: [] }), true)
})

// The root does not encode the tree size: a proof can verify against a larger claimed size (index 0 of three leaves
// under size 4). The size is bound by the signed checkpoint, which carries size and root together (C2SP
// tlog-checkpoint); a caller takes both from one checkpoint.
test('the size is bound by the checkpoint, not by the root (pinned)', () => {
  const d = [1, 2, 3].map((x) => Uint8Array.from([x]))
  const args = { leafHash: LEAF(d[0]), index: 0, size: 3, proof: path(0, d), root: mth(d) }
  assert.equal(verifyInclusion(args), true)
  assert.equal(verifyInclusion({ ...args, size: 4 }), true)
})

// Found by checking, not assumed: without the size1 > size2 refusal, a genuine proof from 6 to 11 also verifies from
// 11 to 6, with the roots in their original places. Every pair of sizes up to 20, both ways round.
test('a consistency proof never verifies with the sizes swapped (exhaustive to 20 entries)', () => {
  const d = Array.from({ length: 20 }, (_, i) => Uint8Array.from([i]))
  let checked = 0
  for (let n = 2; n <= 20; n++) {
    for (let m = 1; m < n; m++) {
      const p = consistencyProof(m, d.slice(0, n))
      const [r1, r2] = [mth(d.slice(0, m)), mth(d.slice(0, n))]
      assert.equal(verifyConsistency({ size1: m, size2: n, root1: r1, root2: r2, proof: p }), true)
      for (const [a, b] of [[r1, r2], [r2, r1]]) {
        assert.equal(verifyConsistency({ size1: n, size2: m, root1: a, root2: b, proof: p }), false, `${n} to ${m}`)
        checked++
      }
    }
  }
  assert.equal(checked, 380)
})

// Trees past 2^31 entries, where a 32-bit shift would go wrong. With every leaf the same, a subtree's root depends
// only on its size, so MTH, PATH and PROOF of trees up to 2^53 - 1 take a few dozen hashes (same recursions as above).
test('trees of up to 2^53 - 1 identical entries: genuine proofs verify, changed ones do not', () => {
  const leaf = LEAF(Uint8Array.from([7]))
  const memo = new Map()
  const root = (n) => {
    if (n === 1) return leaf
    if (!memo.has(n)) { const k = split(n); memo.set(n, NODE(root(k), root(n - k))) }
    return memo.get(n)
  }
  const pathOf = (m, n) => {
    if (n === 1) return []
    const k = split(n)
    return m < k ? [...pathOf(m, k), root(n - k)] : [...pathOf(m - k, n - k), root(k)]
  }
  const sub = (m, n, b) => {
    if (m === n) return b ? [] : [root(n)]
    const k = split(n)
    return m <= k ? [...sub(m, k, b), root(n - k)] : [...sub(m - k, n - k, false), root(k)]
  }
  const sizes = [2 ** 31 + 1, 2 ** 32, 2 ** 32 + 5, 2 ** 40 + 3, 2 ** 53 - 1]
  for (const n of sizes) {
    for (const m of [0, 2 ** 31 + 7, n - 1].filter((i) => i < n)) {
      const p = pathOf(m, n)
      assert.equal(verifyInclusion({ leafHash: leaf, index: m, size: n, proof: p, root: root(n) }), true, `inclusion ${m} of ${n}`)
      assert.equal(verifyInclusion({ leafHash: leaf, index: m, size: n, proof: p.slice(1), root: root(n) }), false, `short ${m} of ${n}`)
    }
    for (const m of [1, 2 ** 31, 2 ** 31 + 3, n - 1].filter((s) => s < n)) {
      const p = sub(m, n, true)
      assert.equal(verifyConsistency({ size1: m, size2: n, root1: root(m), root2: root(n), proof: p }), true, `consistency ${m} to ${n}`)
      assert.equal(verifyConsistency({ size1: m, size2: n, root1: root(m), root2: root(n), proof: p.slice(0, -1) }), false, `short ${m} to ${n}`)
    }
  }
})
