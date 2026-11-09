// Delegations (SPEC §5 D1–D7): a root's passkey lets an Ed25519 key act for the identity, at one audience, for some
// scopes, for a bounded time; the key countersigns its acceptance.
//
// checkDelegation opens the envelope itself, so the record id it checks is the id of the bytes it was given. Whether
// the root has authority under the named membership (R6), and whether the caller's view is fresh, are the verifier's.
import { open, EnvelopeError } from './envelope.js'
import { checkRootAssertion } from './assertion.js'
import { checkEd25519, checkEd25519Key } from './ed25519.js'
import { isCanonicalOrigin } from './origin.js'
import { rootIdOf } from './root.js'
import { fromHex, refuse, accept } from './bytes.js'

const { apply } = Reflect
const { freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { set } = Object.getPrototypeOf(Uint8Array.prototype)
const textEncode = TextEncoder.prototype.encode
const UTF8 = new TextEncoder()
const { isRefusal } = EnvelopeError
const Bytes = Uint8Array

const BODY_KEYS = freeze(['agent', 'aud', 'exp', 'identity', 'membership', 'nbf', 'root', 'scopes', 'subject'])
const SIG_KEYS = freeze(['root', 'subject'])
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const SCOPE = /^[a-z][a-z0-9_.:-]{0,63}$/
const MAX_SCOPES = 16
const ACCEPT_PREFIX = 'muid/v1/accept\n'

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
  // The agent's name (decision 13) is of a scope's form.
  return hasKeys(b, BODY_KEYS) && isHex(SCOPE, b.agent) && isHex(HEX64, b.identity) && isHex(HEX64, b.membership) && isHex(HEX64, b.root) &&
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
  apply(set, out, [apply(textEncode, UTF8, [ACCEPT_PREFIX])])
  apply(set, out, [fromHex(id), ACCEPT_PREFIX.length])
  return out
}

const ROOT_KEY = /^04[0-9a-f]{128}$/

// Each field is read once, so a getter cannot change a value between checks.
function readContext (ctx) {
  if (typeof ctx !== 'object' || ctx === null) return undefined
  const { rootKey, rpId, origin, now, skew, maxLifetime } = ctx
  if (!isHex(ROOT_KEY, rootKey) || typeof rpId !== 'string' || typeof origin !== 'string' || !isTime(now) ||
    !isTime(skew) || !isTime(maxLifetime)) return undefined
  return { rootKey, rpId, origin, now, skew, maxLifetime }
}

export function checkDelegation (text, context) {
  const ctx = readContext(context)
  if (ctx === undefined) {
    throw new TypeError('context must hold a P-256 rootKey, rpId and origin, and non-negative now, skew, maxLifetime')
  }
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
  // The key the caller gives must be the key of the root the delegation names (W3), under this rp ID.
  if (rootIdOf(ctx.rpId, ctx.rootKey) !== b.root) return refuse('root')
  const root = checkRootAssertion(sig.root, { record: id, rpId: ctx.rpId, origin: ctx.origin, key: ctx.rootKey })
  if (!root.ok) return root
  return checkEd25519(sig.subject, acceptMessage(id), b.subject).ok ? accept({ id, body: b }) : refuse('subject-consent')
}
