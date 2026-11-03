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

// UTF-8 of the text, then the bytes of the hex.
function concat (text, hex) {
  const head = apply(textEncode, UTF8, [text])
  const out = new Bytes(head.length + hex.length / 2)
  apply(set, out, [head])
  apply(set, out, [fromHex(hex), head.length])
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
