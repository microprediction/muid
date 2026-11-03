// Ed25519 keys and signatures (SPEC §2 K1, K2, K4, K5).
//
// checkEd25519 never throws for any sig or key value: every failure, including a throw from the library, is a
// reason (K2). Points are decoded canonically (zip215: false) and must be of full prime order — key and R alike —
// so that every engine reaches the same verdict (K1, K4).
import { ed25519 } from '@noble/curves/ed25519.js'
import { fromHex, snapshot, verdict } from './bytes.js'

const { Point } = ed25519
const L = Point.Fn.ORDER
const libraryVerify = ed25519.verify
const { apply } = Reflect
const { freeze, getPrototypeOf } = Object
const { exec } = RegExp.prototype
const { subarray } = getPrototypeOf(Uint8Array.prototype)
const toBigInt = BigInt
const KEY_HEX = /^[0-9a-f]{64}$/
const SIG_HEX = /^[0-9a-f]{128}$/
// Defence in depth: the checks below already admit only canonical, prime-order points, on which ZIP-215 and strict
// verification agree, so changing this option changes no result (tests/meta/ed25519-twins.test.mjs).
// Stryker disable next-line ObjectLiteral,BooleanLiteral: equivalent, as above
const VERIFY_OPTIONS = freeze({ __proto__: null, zip215: false })

const isHex = (re, x) => typeof x === 'string' && apply(exec, re, [x]) !== null

// The reason a point fails K1/K4, or undefined if it is a canonical point of prime order. A throw is a reject (K2).
function pointFault (bytes, prefix) {
  try {
    const p = Point.fromBytes(bytes, false)
    if (p.isSmallOrder()) return `${prefix}-small-order`
    if (!p.isTorsionFree()) return `${prefix}-mixed-order`
    return undefined
  } catch { /* reported below */ }
  return `${prefix}-point`
}

function verifies (sigBytes, message, keyBytes) {
  try {
    if (libraryVerify(sigBytes, message, keyBytes, VERIFY_OPTIONS) === true) return true
  } catch { /* a throw is a reject (K2) */ }
  return false
}

function scalarInRange (bytes) {
  let s = 0n
  for (let i = bytes.length - 1; i >= 0; i--) s = (s << 8n) | toBigInt(bytes[i])
  return s < L
}

// K1 on its own: the first of K5's key reasons, or undefined for a usable key.
function keyReason (key) {
  if (!isHex(KEY_HEX, key)) return 'key-encoding'
  return pointFault(fromHex(key), 'key')
}

// K5's key checks alone, for keys that are named before anything is signed with them (a delegation's subject).
export function checkEd25519Key (key) {
  return verdict(keyReason(key))
}

export function checkEd25519 (sig, message, key) {
  const msg = snapshot(message)
  if (msg === undefined) throw new TypeError('message must be a Uint8Array')
  const keyFault = keyReason(key)
  if (keyFault) return verdict(keyFault)
  const keyBytes = fromHex(key)
  if (!isHex(SIG_HEX, sig)) return verdict('sig-encoding')
  const sigBytes = fromHex(sig)
  const rFault = pointFault(apply(subarray, sigBytes, [0, 32]), 'sig-r')
  if (rFault) return verdict(rFault)
  if (!scalarInRange(apply(subarray, sigBytes, [32]))) return verdict('sig-s-range')
  return verdict(verifies(sigBytes, msg, keyBytes) ? undefined : 'sig-invalid')
}
