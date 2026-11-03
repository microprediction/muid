// P-256 signatures, as passkeys produce them (SPEC §2 K2, K6).
//
// checkP256 never throws for any sig or key value. The key is the uncompressed point only; the signature is strict
// DER; S may be high, because passkeys emit both forms (so a signature is malleable: nothing is keyed on it, §2).
import { p256 } from '@noble/curves/nist.js'

const { Point, Signature } = p256
const libraryVerify = p256.verify
const { apply } = Reflect
const { create, freeze, getOwnPropertyDescriptor, getPrototypeOf } = Object
const { exec } = RegExp.prototype
const { charCodeAt } = String.prototype
const Bytes = Uint8Array
const tagOf = getOwnPropertyDescriptor(getPrototypeOf(Uint8Array.prototype), Symbol.toStringTag).get
const KEY_HEX = /^04[0-9a-f]{128}$/
const OPTIONS = freeze({ __proto__: null, format: 'der', lowS: false, prehash: true })

function result (reason) {
  const out = create(null)
  out.ok = reason === undefined
  if (reason !== undefined) out.reason = reason
  return freeze(out)
}

// A copy made from the internal slots, so a subclass cannot change what is checked while it is being checked.
// Undefined for anything that is not a live Uint8Array (a detached buffer, a lookalike).
function snapshot (x) {
  // Stryker disable next-line ArrayDeclaration: equivalent; a getter takes no arguments
  if (apply(tagOf, x, []) !== 'Uint8Array') return undefined
  try {
    return new Bytes(x)
  } catch { /* detached */ }
  return undefined
}

// Only called on text that matched KEY_HEX.
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

function isPoint (bytes) {
  try {
    Point.fromBytes(bytes)
    return true
  } catch { /* reported by the caller */ }
  return false
}

function isDer (sig) {
  try {
    Signature.fromBytes(sig, 'der')
    return true
  } catch { /* reported by the caller */ }
  return false
}

function verifies (sig, message, key) {
  try {
    if (libraryVerify(sig, message, key, OPTIONS) === true) return true
  } catch { /* a throw is a reject (K2) */ }
  return false
}

export function checkP256 (sig, message, key) {
  const msg = snapshot(message)
  if (msg === undefined) throw new TypeError('message must be a Uint8Array')
  if (typeof key !== 'string' || apply(exec, KEY_HEX, [key]) === null) return result('key-encoding')
  const keyBytes = fromHex(key)
  if (!isPoint(keyBytes)) return result('key-point')
  const sigBytes = snapshot(sig) // undefined fails isDer
  if (!isDer(sigBytes)) return result('sig-encoding')
  return result(verifies(sigBytes, msg, keyBytes) ? undefined : 'sig-invalid')
}
