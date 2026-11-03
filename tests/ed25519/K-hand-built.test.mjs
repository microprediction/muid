// K1, K4 on constructed inputs: small-order and mixed-order keys and R values, the identity, non-canonical y.
// Inputs are built with @noble/curves primitives (the dependency, not our code); expected reasons are written here.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha512 } from '@noble/hashes/sha2.js'
import { accepts, rejects, hex, bytes, SMALL_ORDER } from './helpers.mjs'

const { Point } = ed25519
const L = Point.Fn.ORDER
const le = (b) => b.reduceRight((acc, x) => (acc << 8n) | BigInt(x), 0n)
const toLe = (n) => { const out = new Uint8Array(32); for (let i = 0; i < 32; i++) { out[i] = Number(n & 255n); n >>= 8n } return out }

const secret = bytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60') // RFC 8032 TEST 1
const { scalar: a, point: A } = ed25519.utils.getExtendedPublicKey(secret)
const msg = new TextEncoder().encode('muid test message')
const T8 = Point.fromBytes(bytes(SMALL_ORDER[4])) // a point of order 8

// A signature whose R carries a small-order component, made to satisfy the cofactored equation.
function signWithTorsionR (key, scalar) {
  const r = 123456789n
  const R = Point.BASE.multiply(r).add(T8)
  const k = le(sha512(new Uint8Array([...R.toBytes(), ...key.toBytes(), ...msg]))) % L
  const S = (r + k * scalar) % L
  return hex(R.toBytes()) + hex(toLe(S))
}

test('the published small-order points are small-order and canonical (input sanity)', () => {
  for (const p of SMALL_ORDER) {
    const P = Point.fromBytes(bytes(p))
    assert.equal(P.isSmallOrder(), true, p)
    assert.equal(hex(P.toBytes()), p, p)
  }
  assert.equal(new Set(SMALL_ORDER).size, 8)
})

test('an honest signature by the base key verifies (control)', () => {
  accepts(hex(ed25519.sign(msg, secret)), msg, hex(A.toBytes()), 'control')
})

test('every small-order point is refused as a key, before the signature is looked at', () => {
  for (const p of SMALL_ORDER) rejects('00'.repeat(64), msg, p, 'key-small-order', p)
})

test('a key with a small-order component is refused as mixed-order', () => {
  for (const p of SMALL_ORDER.slice(1)) {
    const mixed = hex(A.add(Point.fromBytes(bytes(p))).toBytes())
    rejects(hex(ed25519.sign(msg, secret)), msg, mixed, 'key-mixed-order', p)
  }
})

test('an R with a small-order component is refused (K4), though ed25519.verify with zip215: false accepts it', () => {
  const sig = signWithTorsionR(A, a)
  assert.equal(ed25519.verify(bytes(sig), msg, A.toBytes(), { zip215: false }), true, 'the library accepts it')
  rejects(sig, msg, hex(A.toBytes()), 'sig-r-mixed-order', 'torsion in R')
})

test('every small-order point is refused as R', () => {
  for (const p of SMALL_ORDER) rejects(p + '00'.repeat(32), msg, hex(A.toBytes()), 'sig-r-small-order', p)
})

test('a non-canonical y (y = p, and y = p + 1) is refused as key and as R', () => {
  const yp = 'ed' + 'ff'.repeat(30) + '7f' // p = 2^255 - 19, little-endian
  const yp1 = 'ee' + 'ff'.repeat(30) + '7f'
  for (const y of [yp, yp1]) {
    rejects('00'.repeat(64), msg, y, 'key-point', `key ${y}`)
    rejects(y + '00'.repeat(32), msg, hex(A.toBytes()), 'sig-r-point', `R ${y}`)
  }
})

test('a y with no x on the curve is refused as key and as R', () => {
  const notOnCurve = '02' + '00'.repeat(31)
  assert.throws(() => Point.fromBytes(bytes(notOnCurve)))
  rejects('00'.repeat(64), msg, notOnCurve, 'key-point', 'key')
  rejects(notOnCurve + '00'.repeat(32), msg, hex(A.toBytes()), 'sig-r-point', 'R')
})

test('S = L and S = L + 1 are out of range; S = L - 1 is in range (and simply wrong)', () => {
  const R = hex(ed25519.sign(msg, secret)).slice(0, 64)
  rejects(R + hex(toLe(L)), msg, hex(A.toBytes()), 'sig-s-range', 'S = L')
  rejects(R + hex(toLe(L + 1n)), msg, hex(A.toBytes()), 'sig-s-range', 'S = L + 1')
  rejects(R + hex(toLe(L - 1n)), msg, hex(A.toBytes()), 'sig-invalid', 'S = L - 1')
})

test('S + L, which a library reducing S would accept, is refused', () => {
  const sig = ed25519.sign(msg, secret)
  const S = le(sig.slice(32))
  const big = S + L
  if (big < 2n ** 256n) rejects(hex(sig.slice(0, 32)) + hex(toLe(big)), msg, hex(A.toBytes()), 'sig-s-range', 'S + L')
})
