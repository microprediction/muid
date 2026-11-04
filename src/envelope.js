// Envelope and record id (SPEC §4, V1–V4).
//
// open(text, type) checks the envelope in V4 order and returns the received payload text unchanged: signatures are
// checked over signedBytes(payload) by the record type's own rules, and nothing here re-serialises what it opened.
import { sha256 } from '@noble/hashes/sha2.js'
import { encode, decode } from './encode.js'
import { toHex } from './bytes.js'

const { apply } = Reflect
const { create, defineProperty, freeze, keys } = Object
const { isArray } = Array
const { includes } = Array.prototype
const { isWellFormed } = String.prototype
const stringify = JSON.stringify
const textEncode = TextEncoder.prototype.encode
const UTF8 = new TextEncoder()

export const MAX_PAYLOAD = 49152

const PREFIX = 'muid/v1\n'
const TYPES = freeze(['root', 'delegation', 'attestation', 'membership', 'freeze', 'contest', 'anchor', 'settlement',
  'head', 'claim', 'revocation', 'receipt'])

export class EnvelopeError extends Error {
  #refusal
  static isRefusal (e) {
    return typeof e === 'object' && e !== null && #refusal in e
  }

  constructor (reason) {
    super(`envelope refused: ${reason}`)
    defineProperty(this, 'reason', { __proto__: null, value: reason, enumerable: true })
  }
}
defineProperty(EnvelopeError.prototype, 'name', { __proto__: null, value: 'EnvelopeError' })
freeze(EnvelopeError)
freeze(EnvelopeError.prototype)

function fail (reason) {
  throw new EnvelopeError(reason)
}

function knownType (type) {
  if (!apply(includes, TYPES, [type])) throw new TypeError('unknown record type')
}

const isObject = (x) => typeof x === 'object' && x !== null && !isArray(x)

// A revoked proxy throws from isArray; it is not an object body either.
function requireObjectBody (body) {
  try {
    if (isObject(body)) return
  } catch { /* not an object body */ }
  throw new TypeError('body must be an object')
}

// V5: the UTF-8 bytes a payload occupies inside the envelope, escapes included.
const envelopeBytes = (payload) => apply(textEncode, UTF8, [stringify(payload)]).length - 2

function sameKeys (o, expected) {
  const k = keys(o)
  if (k.length !== expected.length) return false
  // Stryker disable next-line EqualityOperator: equivalent; at i === length both sides are undefined
  for (let i = 0; i < k.length; i++) if (k[i] !== expected[i]) return false
  return true
}

export function signedBytes (payload) {
  // Stryker disable next-line ArrayDeclaration: equivalent; isWellFormed takes no arguments
  if (typeof payload !== 'string' || !apply(isWellFormed, payload, [])) {
    throw new TypeError('payload must be a well-formed string')
  }
  return apply(textEncode, UTF8, [PREFIX + payload])
}

const idOf = (payload) => toHex(sha256(signedBytes(payload)))

export function open (text, type) {
  knownType(type)
  let env
  try {
    env = decode(text)
  } catch {
    fail('envelope-encoding')
  }
  const root = type === 'root'
  if (!sameKeys(env, root ? ['payload'] : ['payload', 'sig'])) fail('envelope-shape')
  if (typeof env.payload !== 'string' || (!root && !isObject(env.sig))) fail('envelope-shape')
  if (envelopeBytes(env.payload) > MAX_PAYLOAD) fail('payload-size')
  let p
  try {
    p = decode(env.payload)
  } catch {
    fail('payload-encoding')
  }
  if (!sameKeys(p, ['body', 'type', 'v']) || !isObject(p.body)) fail('payload-shape')
  if (p.v !== 1) fail('version')
  if (p.type !== type) fail('type')
  const out = create(null)
  out.id = idOf(env.payload)
  out.type = type
  out.body = p.body
  if (!root) out.sig = env.sig
  out.payload = env.payload
  return freeze(out)
}

export function seal (type, body) {
  knownType(type)
  requireObjectBody(body)
  const payload = encode({ body, type, v: 1 })
  if (envelopeBytes(payload) > MAX_PAYLOAD) fail('payload-size')
  const out = create(null)
  out.payload = payload
  out.id = idOf(payload)
  return freeze(out)
}

export function wrap (payload, sig) {
  if (typeof payload !== 'string') throw new TypeError('payload must be a string')
  return sig === undefined ? encode({ payload }) : encode({ payload, sig })
}
