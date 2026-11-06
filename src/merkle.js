// Merkle tree proofs (RFC 9162 §2.1), SHA-256, as C2SP tlog-tiles and tlog-checkpoint use them: inclusion
// (§2.1.3.2) and consistency (§2.1.4.2). A proof comes from whoever presents it, so any input that is not a genuine
// proof gives false, and nothing throws. Sizes reach 2^53 - 1, so halving is arithmetic, never a 32-bit shift.
import { sha256 } from '@noble/hashes/sha2.js'
import { snapshot } from './bytes.js'

const { isSafeInteger } = Number
const { isArray } = Array
const Bytes = Uint8Array
const MAX_PROOF = 64 // a tree of fewer than 2^53 entries needs at most 54 hashes in either proof
const EMPTY = sha256(new Bytes(0)) // the root of the empty tree (§2.1.1)

const odd = (n) => n % 2 === 1
const half = (n) => (n - (n % 2)) / 2

function node (left, right) {
  const b = new Bytes(65)
  b[0] = 1
  b.set(left, 1)
  b.set(right, 33)
  return sha256(b)
}

function same (a, b) {
  let d = 0
  // Stryker disable next-line EqualityOperator: equivalent; past the end both reads give undefined, and their xor is 0
  for (let i = 0; i < 32; i++) d |= a[i] ^ b[i]
  return d === 0
}

// The fields named, and the proof's elements, as read from x: the only step that touches the caller's object, so the
// only one that can throw (a Proxy, a revoked one, a getter). Undefined if it does, or if the proof is not an array
// of at most MAX_PROOF, whose elements are then not read.
function raw (x, names) {
  try {
    // Stryker disable next-line ArrayDeclaration: equivalent; every element is assigned below
    const out = []
    // Stryker disable next-line EqualityOperator: equivalent; the extra element read is overwritten by the proof
    for (let i = 0; i < names.length; i++) out[i] = x[names[i]]
    const list = x.proof
    if (!isArray(list)) return undefined
    const n = list.length // read once: a Proxy may answer differently each time
    // Stryker disable next-line EqualityOperator: equivalent; no proof of MAX_PROOF hashes is genuine
    if (!isSize(n) || n > MAX_PROOF) return undefined
    const proof = []
    for (let i = 0; i < n; i++) proof[i] = list[i]
    out[names.length] = proof
    return out
  } catch { /* a hostile object: undefined */ }
}

const isSize = (n) => isSafeInteger(n) && n >= 0
function isHash (b) {
  return b !== undefined && b.length === 32
}

// [size, size, hash, hash, proof] checked and copied, or undefined. Nothing here can throw.
function read (x, names) {
  const r = raw(x, names)
  if (r === undefined || !isSize(r[0]) || !isSize(r[1])) return undefined
  const h = [snapshot(r[2]), snapshot(r[3])]
  if (!isHash(h[0]) || !isHash(h[1])) return undefined
  const proof = []
  for (let i = 0; i < r[4].length; i++) {
    proof[i] = snapshot(r[4][i])
    if (!isHash(proof[i])) return undefined
  }
  return [r[0], r[1], h[0], h[1], proof]
}

// The leaf hash of an entry (§2.1.1): SHA-256 of 0x00 and the entry.
export function leafHash (entry) {
  const e = snapshot(entry)
  if (e === undefined) throw new TypeError('entry must be a Uint8Array')
  const b = new Bytes(e.length + 1)
  b.set(e, 1)
  return sha256(b)
}

// §2.1.3.2: { leafHash, index, size, proof, root } proves the entry at index is in the tree of that size and root.
export function verifyInclusion (x) {
  const v = read(x, ['index', 'size', 'leafHash', 'root'])
  if (v === undefined) return false
  const [index, size, leaf, root, proof] = v
  if (index >= size) return false
  let fn = index
  let sn = size - 1
  let r = leaf
  for (let i = 0; i < proof.length; i++) {
    // Stryker disable next-line ConditionalExpression: equivalent; a further element changes r, which could then
    // equal the root only through a SHA-256 preimage. Kept as RFC 9162 states it.
    if (sn === 0) return false
    if (odd(fn) || fn === sn) {
      r = node(proof[i], r)
      // RFC 9162 also stops at fn = 0, which cannot occur: here fn is even only when fn = sn > 0, and halving a
      // positive even number reaches an odd one before 0.
      while (!odd(fn)) {
        fn = half(fn)
        sn = half(sn)
      }
    } else {
      r = node(r, proof[i])
    }
    fn = half(fn)
    sn = half(sn)
  }
  return sn === 0 && same(r, root)
}

// §2.1.4.2: { size1, size2, root1, root2, proof } proves the tree of size1 and root1 is a prefix of the tree of
// size2 and root2. Equal sizes need equal roots and no proof; the empty tree, its own root and no proof.
export function verifyConsistency (x) {
  const v = read(x, ['size1', 'size2', 'root1', 'root2'])
  if (v === undefined) return false
  const [size1, size2, root1, root2, proof] = v
  if (size1 > size2) return false // not redundant: a genuine proof from 6 to 11 also passes from 11 to 6
  if (size1 === size2) return proof.length === 0 && same(root1, root2)
  if (size1 === 0) return proof.length === 0 && same(root1, EMPTY)
  // Stryker disable next-line ConditionalExpression: equivalent; with no proof the loop is skipped and sn stays
  // positive, since size2 > size1. Kept as RFC 9162's first step.
  if (proof.length === 0) return false
  let p = size1
  while (!odd(p)) p = half(p)
  const path = p === 1 ? [root1, ...proof] : proof // size1 a power of two: its root starts the path
  let fn = size1 - 1
  let sn = size2 - 1
  while (odd(fn)) {
    fn = half(fn)
    sn = half(sn)
  }
  let fr = path[0]
  let sr = path[0]
  for (let i = 1; i < path.length; i++) {
    // Stryker disable next-line ConditionalExpression: equivalent, as in verifyInclusion.
    if (sn === 0) return false
    if (odd(fn) || fn === sn) {
      fr = node(path[i], fr)
      sr = node(path[i], sr)
      while (!odd(fn)) { // fn = sn > 0 here, as in verifyInclusion
        fn = half(fn)
        sn = half(sn)
      }
    } else {
      sr = node(sr, path[i])
    }
    fn = half(fn)
    sn = half(sn)
  }
  return sn === 0 && same(fr, root1) && same(sr, root2)
}
