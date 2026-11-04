// P-256 signatures, as passkeys produce them (SPEC §2 K2, K6).
//
// checkP256 never throws for any sig or key value. The key is the uncompressed point only; the signature is strict
// DER; S may be high, because passkeys emit both forms (so a signature is malleable: nothing is keyed on it, §2).
import { p256 } from '@noble/curves/nist.js'
import { fromHex, snapshot, verdict } from './bytes.js'

const { Point, Signature } = p256
const libraryVerify = p256.verify
const { apply } = Reflect
const { freeze } = Object
const { exec } = RegExp.prototype
const KEY_HEX = /^04[0-9a-f]{128}$/
const OPTIONS = freeze({ __proto__: null, format: 'der', lowS: false, prehash: true })

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

// K6's key checks: the first key reason, or undefined for a usable key.
function keyReason (key) {
  if (typeof key !== 'string' || apply(exec, KEY_HEX, [key]) === null) return 'key-encoding'
  return isPoint(fromHex(key)) ? undefined : 'key-point'
}

// K6's key checks alone, for a key named before anything is signed with it (a root's pub).
export function checkP256Key (key) {
  return verdict(keyReason(key))
}

export function checkP256 (sig, message, key) {
  const msg = snapshot(message)
  if (msg === undefined) throw new TypeError('message must be a Uint8Array')
  const keyFault = keyReason(key)
  if (keyFault) return verdict(keyFault)
  const keyBytes = fromHex(key)
  const sigBytes = snapshot(sig) // undefined fails isDer
  if (!isDer(sigBytes)) return verdict('sig-encoding')
  return verdict(verifies(sigBytes, msg, keyBytes) ? undefined : 'sig-invalid')
}
