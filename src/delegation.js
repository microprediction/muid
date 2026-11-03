// Delegations (SPEC §5 D1–D7): a root's passkey lets an Ed25519 key act for the identity, at one audience, for some
// scopes, for a bounded time; the key countersigns its acceptance.
//
// checkDelegation opens the envelope itself, so the record id it checks is the id of the bytes it was given. Whether
// the root has authority under the named membership (R6), and whether the caller's view is fresh, are the verifier's.
import { open, EnvelopeError } from './envelope.js'
import { checkRootAssertion } from './assertion.js'
import { checkEd25519, checkEd25519Key } from './ed25519.js'
import { isCanonicalOrigin } from './origin.js'

const { apply } = Reflect
const { create, freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { charCodeAt } = String.prototype
const { isRefusal } = EnvelopeError
const Bytes = Uint8Array

const BODY_KEYS = freeze(['aud', 'exp', 'identity', 'membership', 'nbf', 'root', 'scopes', 'subject'])
const SIG_KEYS = freeze(['root', 'subject'])
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const SCOPE = /^[a-z][a-z0-9_.:-]{0,63}$/
const MAX_SCOPES = 16
const ACCEPT_PREFIX = 'muid/v1/accept\n'

function refuse (reason) {
  const out = create(null)
  out.ok = false
  out.reason = reason
  return freeze(out)
}

const isHex = (re, x) => typeof x === 'string' && apply(exec, re, [x]) !== null
const isTime = (x) => isSafeInteger(x) && x >= 0

// No keys but these, in canonical order: a decoded object lists its keys sorted, and open has already made body and
// sig plain objects. A missing key fails its own field check.
function hasKeys (o, keys) {
  let i = 0
  for (const k in o) if (k !== keys[i++]) return false
  return true
}

function bodyOk (b) {
  return hasKeys(b, BODY_KEYS) && isHex(HEX64, b.identity) && isHex(HEX64, b.membership) && isHex(HEX64, b.root) &&
    isHex(HEX64, b.subject) && typeof b.aud === 'string' && isArray(b.scopes) && isTime(b.nbf) && isTime(b.exp)
}

function scopesOk (scopes) {
  if (scopes.length < 1 || scopes.length > MAX_SCOPES) return false
  for (let i = 0; i < scopes.length; i++) {
    if (!isHex(SCOPE, scopes[i])) return false
    if (i > 0 && !(scopes[i - 1] < scopes[i])) return false
  }
  return true
}

// D6's message: the accept prefix, then the record id as 32 raw bytes.
function acceptMessage (id) {
  const out = new Bytes(ACCEPT_PREFIX.length + 32)
  // Stryker disable next-line EqualityOperator: equivalent; a write past the end of a typed array is ignored
  for (let i = 0; i < ACCEPT_PREFIX.length; i++) out[i] = apply(charCodeAt, ACCEPT_PREFIX, [i])
  // Stryker disable next-line EqualityOperator: equivalent; a write past the end of a typed array is ignored
  for (let i = 0; i < 32; i++) {
    let byte = 0
    for (let j = 0; j < 2; j++) {
      const c = apply(charCodeAt, id, [2 * i + j])
      byte = byte * 16 + (c <= 57 ? c - 48 : c - 87)
    }
    out[ACCEPT_PREFIX.length + i] = byte
  }
  return out
}

function contextOk (ctx) {
  return typeof ctx === 'object' && ctx !== null && typeof ctx.rootKey === 'string' && typeof ctx.rpId === 'string' &&
    typeof ctx.origin === 'string' && isTime(ctx.now) && isTime(ctx.skew) && isTime(ctx.maxLifetime)
}

export function checkDelegation (text, ctx) {
  if (!contextOk(ctx)) throw new TypeError('context must hold rootKey, rpId, origin and non-negative now, skew, maxLifetime')
  let record
  try {
    record = open(text, 'delegation')
  } catch (e) {
    // Anything else can only come from built-ins patched in the page (§4 residual): fail closed.
    return refuse(isRefusal(e) ? e.reason : 'envelope-encoding')
  }
  const { id, body: b, sig } = record
  if (!bodyOk(b) || !hasKeys(sig, SIG_KEYS) || !isHex(HEX128, sig.subject)) return refuse('delegation-shape')
  if (!scopesOk(b.scopes)) return refuse('scopes')
  if (!isCanonicalOrigin(b.aud)) return refuse('aud')
  if (!checkEd25519Key(b.subject).ok) return refuse('subject-key')
  if (b.exp <= b.nbf || b.exp - b.nbf > ctx.maxLifetime) return refuse('lifetime')
  if (ctx.now < b.nbf - ctx.skew) return refuse('not-yet')
  if (ctx.now >= b.exp) return refuse('expired')
  const root = checkRootAssertion(sig.root, { record: id, rpId: ctx.rpId, origin: ctx.origin, key: ctx.rootKey })
  if (!root.ok) return root
  return checkEd25519(sig.subject, acceptMessage(id), b.subject).ok ? root : refuse('subject-consent')
}
