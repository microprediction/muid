// Roots and identities (SPEC §5): a root record is unsigned; its id is derived from its key and rp ID, and an identity
// id from its first root id.
import { sha256 } from '@noble/hashes/sha2.js'
import { open, EnvelopeError } from './envelope.js'
import { checkP256Key } from './p256.js'
import { fromHex, toHex, refuse, accept } from './bytes.js'

const { apply } = Reflect
const { freeze } = Object
const { exec } = RegExp.prototype
const { isRefusal } = EnvelopeError
const Bytes = Uint8Array
const { set } = Object.getPrototypeOf(Uint8Array.prototype)
const ID = /^[0-9a-f]{64}$/
const KEYS = freeze(['pub', 'rp_id'])
const textEncode = TextEncoder.prototype.encode
const UTF8 = new TextEncoder()

// The text's UTF-8, the hex as raw bytes, then the tail's UTF-8.
function concat (text, hex, tail = '') {
  const head = apply(textEncode, UTF8, [text])
  const end = apply(textEncode, UTF8, [tail])
  const out = new Bytes(head.length + hex.length / 2 + end.length)
  apply(set, out, [head])
  apply(set, out, [fromHex(hex), head.length])
  apply(set, out, [end, head.length + hex.length / 2])
  return out
}

// The root id of a key under an rp ID (both already checked by the caller).
export function rootIdOf (rpId, pub) {
  return toHex(sha256(concat('muid-root\n' + rpId + '\n', pub)))
}

export function identityOf (rootId) {
  if (typeof rootId !== 'string' || apply(exec, ID, [rootId]) === null) throw new TypeError('root id must be 64 lowercase hex')
  return toHex(sha256(concat('muid-identity\n', rootId)))
}

// Decision 13: a light identity's id, derived from its identity and its delegations' agent name.
const AGENT = /^[a-z][a-z0-9_.:-]{0,63}$/
export function agentIdOf (identity, agent) {
  if (typeof identity !== 'string' || apply(exec, ID, [identity]) === null || typeof agent !== 'string' ||
    apply(exec, AGENT, [agent]) === null) throw new TypeError('an identity id and an agent name')
  return toHex(sha256(concat('muid-agent\n', identity, agent)))
}

export function checkRoot (text, ctx) {
  const rpId = typeof ctx === 'object' && ctx !== null ? ctx.rpId : undefined // read once
  if (typeof rpId !== 'string') throw new TypeError('context must hold an rpId string')
  let record
  try {
    record = open(text, 'root')
  } catch (e) {
    // Anything but a refusal can only come from built-ins patched in the page (§4 residual): fail closed.
    return refuse(isRefusal(e) ? e.reason : 'envelope-encoding')
  }
  const b = record.body
  let i = 0
  for (const k in b) if (k !== KEYS[i++]) return refuse('root-shape')
  if (typeof b.rp_id !== 'string') return refuse('root-shape')
  const key = checkP256Key(b.pub) // a pub that is not a string is key-encoding
  if (key.reason === 'key-encoding') return refuse('root-shape')
  if (b.rp_id !== rpId) return refuse('rp-id')
  if (!key.ok) return key
  return accept({ id: rootIdOf(b.rp_id, b.pub), key: b.pub })
}
