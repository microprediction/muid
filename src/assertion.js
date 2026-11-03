// Root assertions: a passkey's WebAuthn signature over a set of record ids (SPEC §6 W0–W6).
//
// checkRootAssertion never throws for any sig. The sig is first snapshotted through the canonical encoder, so a
// Proxy or accessor is read once or refused, and every later check reads plain frozen data.
import { sha256 } from '@noble/hashes/sha2.js'
import { encode, decode } from './encode.js'
import { checkP256 } from './p256.js'

const { apply } = Reflect
const { create, freeze } = Object
const { isArray } = Array
const { exec } = RegExp.prototype
const { charCodeAt } = String.prototype
const textEncode = TextEncoder.prototype.encode
const UTF8 = new TextEncoder()
const textDecode = TextDecoder.prototype.decode
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const Bytes = Uint8Array
const { set } = Object.getPrototypeOf(Uint8Array.prototype)

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const SEXTET = freeze({ __proto__: null, ...Array.from(ALPHABET, (c, i) => [c.charCodeAt(0), i]).reduce((o, [c, i]) => { o[c] = i; return o }, {}) })
const ID = /^[0-9a-f]{64}$/
const KEYS = freeze(['authenticator_data', 'client_data_json', 'covers', 'signature'])
const MAX_COVERS = 8
// W1: the four fields, compared byte for byte; the challenge and origin are captured for their own reasons.
// Stryker disable next-line Regex: equivalent; without ^ a match after leading bytes leaves the scan below starting
// inside "false", where no member and no closing brace can begin, so it refuses all the same
const PREFIX = /^\{"type":"webauthn\.get","challenge":"([^"\\\x00-\x1f]*)","origin":"([^"\\\x00-\x1f]*)","crossOrigin":false/
// After the prefix, only further string members without escapes or control characters (as JSON requires), none
// with a key of the prefix or topOrigin, then the end.
const MEMBER = /,"([A-Za-z0-9_]{1,64})":"[^"\\\x00-\x1f]*"/y
const RESERVED = freeze(['type', 'challenge', 'origin', 'crossOrigin', 'topOrigin'])
const { includes } = Array.prototype
const UP = 0x01
const UV = 0x04
const BE = 0x08
const BS = 0x10
const FORBIDDEN = 0xe2 // AT, ED and the two reserved bits

// This module only refuses; an accept is K6's result, returned as it is.
function refuse (reason) {
  const out = create(null)
  out.ok = false
  out.reason = reason
  return freeze(out)
}

const utf8 = (text) => apply(textEncode, UTF8, [text])

// All three digests at once. The hash library uses typed-array built-ins when called; if it throws, the assertion
// cannot be verified, and that is a refusal (K2).
function digests (covers, rpId, clientBytes) {
  try {
    let text = 'muid/v1/assert\n'
    for (let i = 0; i < covers.length; i++) text += covers[i] + '\n'
    return { challenge: toB64u(sha256(utf8(text))), rpIdHash: sha256(utf8(rpId)), clientHash: sha256(clientBytes) }
  } catch { /* reported by the caller */ }
  return undefined
}

function toB64u (bytes) {
  let out = ''
  let i = 0
  for (; i + 2 < bytes.length; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    out += ALPHABET[v >> 18] + ALPHABET[(v >> 12) & 63] + ALPHABET[(v >> 6) & 63] + ALPHABET[v & 63]
  }
  if (i + 1 === bytes.length) {
    const v = bytes[i] << 16
    out += ALPHABET[v >> 18] + ALPHABET[(v >> 12) & 63]
  } else if (i + 2 === bytes.length) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8)
    out += ALPHABET[v >> 18] + ALPHABET[(v >> 12) & 63] + ALPHABET[(v >> 6) & 63]
  }
  return out
}

// Canonical unpadded base64url only: decoding then encoding must give the same text back. That rules out any
// character outside the alphabet (it decodes as 0, and re-encodes as 'A'), a length of 1 mod 4, and non-zero
// trailing bits.
function fromB64u (text) {
  if (text.length === 0) return undefined
  const out = new Bytes((text.length * 3) >> 2)
  let acc = 0
  let bits = 0
  let j = 0
  // Stryker disable next-line EqualityOperator: equivalent; one more step reads 0 and writes past the end, ignored
  for (let i = 0; i < text.length; i++) {
    acc = ((acc << 6) | SEXTET[apply(charCodeAt, text, [i])]) & 0xffff
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[j++] = (acc >> bits) & 255
    }
  }
  return toB64u(out) === text ? out : undefined
}

function snapshot (sig) {
  try {
    return decode(encode(sig))
  } catch { /* not plain data */ }
  return undefined
}

// Exactly the four keys, in canonical order (no others: a fifth key meets KEYS[4], undefined), with their types.
function shapeOk (s) {
  if (s === undefined) return false
  let i = 0
  for (const k in s) if (k !== KEYS[i++]) return false
  return isArray(s.covers) && typeof s.authenticator_data === 'string' && typeof s.client_data_json === 'string' &&
    typeof s.signature === 'string'
}

// W0: 1–8 distinct ids in ascending order, including the record's own.
function coversOk (covers, record) {
  if (covers.length > MAX_COVERS) return false
  let mine = false
  for (let i = 0; i < covers.length; i++) {
    const id = covers[i]
    if (typeof id !== 'string' || apply(exec, ID, [id]) === null) return false
    if (i > 0 && !(covers[i - 1] < id)) return false
    if (id === record) mine = true
  }
  return mine
}

// W1 beyond the prefix: string members with other keys, then the closing brace as the last character.
function restOk (text, at) {
  for (;;) {
    if (at === text.length - 1) return apply(charCodeAt, text, [at]) === 125
    MEMBER.lastIndex = at
    const m = apply(exec, MEMBER, [text])
    if (m === null || apply(includes, RESERVED, [m[1]])) return false
    at += m[0].length
  }
}

function sameBytes (a, b) {
  for (let i = 0; i < b.length; i++) if (a[i] !== b[i]) return false
  return true
}

function concat (a, b) {
  const out = new Bytes(a.length + b.length)
  apply(set, out, [a])
  apply(set, out, [b, a.length])
  return out
}

export function checkRootAssertion (sig, ctx) {
  if (typeof ctx !== 'object' || ctx === null || typeof ctx.record !== 'string' || typeof ctx.rpId !== 'string' ||
    typeof ctx.origin !== 'string' || typeof ctx.key !== 'string') {
    throw new TypeError('context must hold record, rpId, origin and key strings')
  }
  const { record, rpId, origin, key } = ctx
  const s = snapshot(sig)
  if (!shapeOk(s)) return refuse('assertion-shape')
  if (!coversOk(s.covers, record)) return refuse('covers')

  const authData = fromB64u(s.authenticator_data)
  const clientBytes = fromB64u(s.client_data_json)
  const signature = fromB64u(s.signature)
  if (authData === undefined || clientBytes === undefined || signature === undefined) return refuse('assertion-encoding')
  let clientText
  try {
    clientText = apply(textDecode, UTF8_STRICT, [clientBytes])
  } catch {
    return refuse('assertion-encoding')
  }

  const m = apply(exec, PREFIX, [clientText])
  if (m === null || !restOk(clientText, m[0].length)) return refuse('client-data')
  const d = digests(s.covers, rpId, clientBytes)
  if (d === undefined) return refuse('sig-invalid')
  if (m[1] !== d.challenge) return refuse('challenge')
  if (m[2] !== origin) return refuse('origin')

  if (authData.length !== 37) return refuse('auth-data-length')
  if (!sameBytes(authData, d.rpIdHash)) return refuse('rp-id')
  const flags = authData[32]
  if (!(flags & UP)) return refuse('user-presence')
  if (!(flags & UV)) return refuse('user-verification')
  if (flags & FORBIDDEN || (flags & BS && !(flags & BE))) return refuse('auth-data-flags')

  return checkP256(signature, concat(authData, d.clientHash), key)
}
