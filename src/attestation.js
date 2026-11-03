// Attestations (SPEC §5 A1, A3, A4): a pinned witness key says a provider account belongs to a root.
//
// checkAttestation opens the envelope itself, so the record it checks is the bytes it was given. Whether the
// sign-in carried proof of possession (A2) is the witness's to enforce before it signs.
import { open, signedBytes, EnvelopeError } from './envelope.js'
import { checkEd25519 } from './ed25519.js'
import { refuse, accept } from './bytes.js'

const { apply } = Reflect
const { freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { charCodeAt } = String.prototype
const { isRefusal } = EnvelopeError

const BODY_KEYS = freeze(['account', 'exp', 'nbf', 'provider', 'root'])
const SIG_KEYS = freeze(['signature', 'witness'])
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const GITHUB = /^[1-9][0-9]{0,19}$/
const GOOGLE = /^[\x21-\x7e]{1,255}$/

const isHex = (re, x) => typeof x === 'string' && apply(exec, re, [x]) !== null
const isTime = (x) => isSafeInteger(x) && x >= 0

// No keys but these, in canonical order (a decoded object lists its keys sorted); a missing key fails its field check.
function onlyKeys (o, keys) {
  let i = 0
  for (const k in o) if (k !== keys[i++]) return false
  return true
}

// dddd-dddd-dddd-dddX: hyphens at 4, 9 and 14, digits elsewhere, and the ISO 7064 MOD 11-2 check last (X for 10).
function orcidOk (id) {
  if (id.length !== 19) return false
  let total = 0
  for (let i = 0; i < 18; i++) {
    const c = apply(charCodeAt, id, [i])
    if (i === 4 || i === 9 || i === 14) {
      if (c !== 45) return false
    } else if (c < 48 || c > 57) {
      return false
    } else {
      total = (total + c - 48) * 2
    }
  }
  const r = (12 - (total % 11)) % 11
  return apply(charCodeAt, id, [18]) === (r === 10 ? 88 : 48 + r)
}

const ACCOUNT = freeze({
  __proto__: null,
  github: (a) => apply(exec, GITHUB, [a]) !== null,
  google: (a) => apply(exec, GOOGLE, [a]) !== null,
  orcid: orcidOk,
})

function readContext (ctx) {
  if (typeof ctx !== 'object' || ctx === null) return undefined
  const { witnessKeys, now, skew, maxLifetime } = ctx
  if (!isArray(witnessKeys) || !isTime(now) || !isTime(skew) || !isTime(maxLifetime)) return undefined
  // Stryker disable next-line ArrayDeclaration: equivalent; every index is assigned below before it is read
  const keys = []
  for (let i = 0; i < witnessKeys.length; i++) {
    const w = witnessKeys[i]
    if (w === null || w === undefined) return undefined // anything else destructures, and fails the key check
    const { key, nbf, exp } = w
    if (!isHex(HEX64, key) || !isTime(nbf) || !isTime(exp)) return undefined
    keys[i] = { key, nbf, exp }
  }
  return { keys, now, skew, maxLifetime }
}

export function checkAttestation (text, context) {
  const ctx = readContext(context)
  if (ctx === undefined) throw new TypeError('context must hold witnessKeys and non-negative now, skew, maxLifetime')
  let record
  try {
    record = open(text, 'attestation')
  } catch (e) {
    // Anything but a refusal can only come from built-ins patched in the page (§4 residual): fail closed.
    return refuse(isRefusal(e) ? e.reason : 'envelope-encoding')
  }
  const { id, body: b, sig, payload } = record
  if (!onlyKeys(b, BODY_KEYS) || !isHex(HEX64, b.root) || typeof b.provider !== 'string' ||
    typeof b.account !== 'string' || !isTime(b.nbf) || !isTime(b.exp) || !onlyKeys(sig, SIG_KEYS) ||
    !isHex(HEX128, sig.signature) || !isHex(HEX64, sig.witness)) return refuse('attestation-shape')
  const form = ACCOUNT[b.provider]
  if (form === undefined) return refuse('provider')
  if (!form(b.account)) return refuse('account')
  if (b.exp <= b.nbf || b.exp - b.nbf > ctx.maxLifetime) return refuse('lifetime')
  if (ctx.now < b.nbf - ctx.skew) return refuse('not-yet')
  if (ctx.now >= b.exp) return refuse('expired')
  let pinned = false
  for (let i = 0; i < ctx.keys.length; i++) {
    const w = ctx.keys[i]
    if (w.key === sig.witness && w.nbf <= ctx.now && ctx.now < w.exp) pinned = true
  }
  if (!pinned) return refuse('witness')
  const verdict = checkEd25519(sig.signature, signedBytes(payload), sig.witness)
  return verdict.ok ? accept({ id, body: b }) : verdict
}
