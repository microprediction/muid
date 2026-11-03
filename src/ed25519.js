// Ed25519 keys and signatures (SPEC §2 K1, K2, K4, K5).
//
// checkEd25519 never throws for any sig or key value: every failure, including a throw from the library, is a
// reason (K2). Points are decoded canonically (zip215: false) and must be of full prime order — key and R alike —
// so that every engine reaches the same verdict (K1, K4).
import { ed25519 } from '@noble/curves/ed25519.js'

const { Point } = ed25519
const L = Point.Fn.ORDER
const libraryVerify = ed25519.verify
const { apply } = Reflect
const { create, freeze, getOwnPropertyDescriptor, getPrototypeOf } = Object
const { exec } = RegExp.prototype
const { charCodeAt } = String.prototype
const Bytes = Uint8Array
const { subarray } = getPrototypeOf(Uint8Array.prototype)
const toBigInt = BigInt
const tagOf = getOwnPropertyDescriptor(getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag).get
const KEY_HEX = /^[0-9a-f]{64}$/
const SIG_HEX = /^[0-9a-f]{128}$/
// Defence in depth: the checks below already admit only canonical, prime-order points, on which ZIP-215 and strict
// verification agree, so changing this option changes no result (tests/meta/ed25519-twins.test.mjs).
// Stryker disable next-line ObjectLiteral,BooleanLiteral: equivalent, as above
const VERIFY_OPTIONS = freeze({ __proto__: null, zip215: false })

function result (reason) {
  const out = create(null)
  out.ok = reason === undefined
  if (reason !== undefined) out.reason = reason
  return freeze(out)
}

const isHex = (re, x) => typeof x === 'string' && apply(exec, re, [x]) !== null

// Only called on text that matched KEY_HEX or SIG_HEX.
function fromHex (text) {
  const out = new Bytes(text.length / 2)
  // Stryker disable next-line EqualityOperator: equivalent; a write past the end of a typed array is ignored
  for (let i = 0; i < out.length; i++) {
    let byte = 0
    for (let j = 0; j < 2; j++) {
      const c = apply(charCodeAt, text, [2 * i + j])
      byte = byte * 16 + (c <= 57 ? c - 48 : c - 87)
    }
    out[i] = byte
  }
  return out
}

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

export function checkEd25519 (sig, message, key) {
  // Stryker disable next-line ArrayDeclaration: equivalent; a getter takes no arguments
  if (apply(tagOf, message, []) !== 'Uint8Array') throw new TypeError('message must be a Uint8Array')
  if (!isHex(KEY_HEX, key)) return result('key-encoding')
  const keyBytes = fromHex(key)
  const keyFault = pointFault(keyBytes, 'key')
  if (keyFault) return result(keyFault)
  if (!isHex(SIG_HEX, sig)) return result('sig-encoding')
  const sigBytes = fromHex(sig)
  const rFault = pointFault(apply(subarray, sigBytes, [0, 32]), 'sig-r')
  if (rFault) return result(rFault)
  if (!scalarInRange(apply(subarray, sigBytes, [32]))) return result('sig-s-range')
  return result(verifies(sigBytes, message, keyBytes) ? undefined : 'sig-invalid')
}
