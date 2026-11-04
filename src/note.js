// Signed notes (C2SP signed-note) and transparency-log checkpoints (C2SP tlog-checkpoint, tlog-cosignature):
// Ed25519 note and log signatures (type 0x01) and timestamped Ed25519 cosignatures (type 0x04). A note comes from
// whoever presents it, so any note that does not verify is refused with a reason; configuration is the caller's,
// so malformed configuration is a programming error.
import { sha256 } from '@noble/hashes/sha2.js'
import { checkEd25519 } from './ed25519.js'
import { toHex, refuse, accept } from './bytes.js'

const { apply } = Reflect
const { freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { isWellFormed, charCodeAt, slice, lastIndexOf, indexOf } = String.prototype
const { sort } = Array.prototype
const encodeText = TextEncoder.prototype.encode
const UTF8 = new TextEncoder()
const { atob, btoa } = globalThis

const LOG = 0x01
const COSIGNATURE = 0x04
const MAX_NOTE = 65536 // characters
const MAX_SIGNATURES = 64 // C2SP signed-note: at least 16
const CONTROL = /[\u0000-\u0009\u000b-\u001f]/ // eslint-disable-line no-control-regex
// No Unicode White_Space (as Go's unicode.IsSpace; JavaScript's \s differs at U+0085 and U+FEFF), plus or control.
const NAME = /^[^\p{White_Space}+\u0000-\u001f]+$/u // eslint-disable-line no-control-regex
const LINE = /^— ([^ ]+) ([A-Za-z0-9+/=]+)$/
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/
const DECIMAL = /^(?:0|[1-9][0-9]*)$/
// Every function applied with NO_ARGS ignores its arguments.
// Stryker disable next-line ArrayDeclaration: equivalent; see the line above.
const NO_ARGS = freeze([])

const utf8 = (s) => apply(encodeText, UTF8, [s])
const matches = (re, s) => apply(exec, re, [s]) !== null

// Standard base64 with padding, canonical only (RFC 4648 §3.5): re-encoding the bytes gives back the text.
function fromBase64 (s) {
  if (!matches(BASE64, s)) return undefined
  const bin = atob(s)
  if (btoa(bin) !== s) return undefined
  const out = new Uint8Array(bin.length)
  // Stryker disable next-line EqualityOperator: equivalent; a write past the end of a typed array is ignored
  for (let i = 0; i < bin.length; i++) out[i] = apply(charCodeAt, bin, [i])
  return out
}

// key ID = SHA-256(key name || 0x0A || signature type || public key)[:4], as eight hex digits.
function keyId (name, type, pub) {
  const n = utf8(name)
  const b = new Uint8Array(n.length + 2 + pub.length)
  b.set(n)
  b[n.length] = 0x0a
  b[n.length + 1] = type
  b.set(pub, n.length + 2)
  return toHex(sha256(b).subarray(0, 4))
}

const isName = (s) => matches(NAME, s) && utf8(s).length <= 255 // a cosigner name's limit (C2SP tlog-cosignature)

// A verifier key `name+hex(key ID)+base64(type || public key)` of the given type, checked; else a programming error.
// The key ID must equal the one computed from the parts, which rules out any other split of the text.
function vkey (text, type) {
  // Stryker disable next-line StringLiteral: equivalent; any text that is not a verifier key is refused below
  const t = typeof text === 'string' ? text : ''
  const a = apply(indexOf, t, ['+'])
  const b = apply(indexOf, t, ['+', a + 1])
  const name = apply(slice, t, [0, a])
  const id = apply(slice, t, [a + 1, b])
  const key = fromBase64(apply(slice, t, [b + 1]))
  if (key === undefined || key.length !== 33 || key[0] !== type || !isName(name) ||
    keyId(name, type, key.subarray(1)) !== id) throw new TypeError(`not a verifier key of type ${type}: ${String(text)}`)
  return { name, id, type, key: toHex(key.subarray(1)) }
}

// { text, lines: [{ name, id, sig }] }, or undefined if the note is not well formed (C2SP signed-note, Format).
function parse (note) {
  // The final-newline test is equivalent to Stryker: a last line without one is refused by the line grammar, or by
  // the blank line before the signatures when parsing wraps round. Kept as the format states it.
  if (typeof note !== 'string' || note.length > MAX_NOTE || !apply(isWellFormed, note, NO_ARGS) || matches(CONTROL, note) ||
    // Stryker disable next-line ConditionalExpression: equivalent; see above
    note[note.length - 1] !== '\n') return undefined
  const split = apply(lastIndexOf, note, ['\n\n'])
  if (split < 0) return undefined
  const text = apply(slice, note, [0, split + 1])
  const lines = []
  let at = split + 2
  while (at < note.length) {
    const end = apply(indexOf, note, ['\n', at]) // found: the note ends with a newline
    if (lines.length === MAX_SIGNATURES) return undefined
    const m = apply(exec, LINE, [apply(slice, note, [at, end])])
    const bytes = m === null ? undefined : fromBase64(m[2])
    if (bytes === undefined || bytes.length < 5 || !isName(m[1])) return undefined
    lines[lines.length] = { name: m[1], id: toHex(bytes.subarray(0, 4)), sig: bytes.subarray(4) }
    at = end + 1
  }
  return lines.length === 0 ? undefined : { text, lines }
}

// The signature lines of known keys, each verified: { at: [index of the line for each key, or -1], time: [...] }, or
// a refusal reason. A repeated line from one known key is refused before anything is verified; unknown keys are
// ignored (C2SP: unless both name and ID match).
function signatures (p, keys) {
  // Stryker disable next-line ArrayDeclaration: equivalent; every element is assigned below before it is read
  const at = []
  // Stryker disable next-line EqualityOperator: equivalent; an element past the keys is never read
  for (let k = 0; k < keys.length; k++) at[k] = -1
  for (let i = 0; i < p.lines.length; i++) {
    for (let k = 0; k < keys.length; k++) {
      if (p.lines[i].name === keys[k].name && p.lines[i].id === keys[k].id) {
        if (at[k] >= 0) return 'duplicate-signature'
        at[k] = i
      }
    }
  }
  // Stryker disable next-line ArrayDeclaration: equivalent; only the elements assigned below are read
  const time = []
  for (let k = 0; k < keys.length; k++) {
    if (at[k] < 0) continue
    const sig = p.lines[at[k]].sig
    let message = p.text
    let bytes = sig
    if (keys[k].type === COSIGNATURE) {
      // An eight-byte big-endian time; one of 2^53 or more cannot be held exactly, so cannot be checked.
      // Stryker disable next-line ArithmeticOperator: equivalent; a time with its first byte set is refused either way
      const high = ((sig[0] * 256 + sig[1]) * 256 + sig[2]) * 256 + sig[3]
      if (high >= 0x200000) return 'signature'
      time[k] = high * 0x100000000 + ((sig[4] * 256 + sig[5]) * 256 + sig[6]) * 256 + sig[7]
      message = 'cosignature/v1\ntime ' + time[k] + '\n' + p.text
      bytes = sig.subarray(8)
    }
    // checkEd25519 refuses a signature that is not 64 bytes (128 hex digits).
    if (!checkEd25519(toHex(bytes), utf8(message), keys[k].key).ok) return 'signature'
  }
  return { at, time }
}

// Verifier keys of one type, none listed twice, by name and ID or by public key: an Ed25519 cosignature does not
// commit to its cosigner's name, so one key under two names would otherwise count twice towards a quorum.
function keyList (list, type) {
  if (!isArray(list)) throw new TypeError('keys must be a list of verifier keys')
  // Stryker disable next-line ArrayDeclaration: equivalent; every element is assigned below
  const out = []
  for (let i = 0; i < list.length; i++) {
    out[i] = vkey(list[i], type)
    // Stryker disable next-line ConditionalExpression: equivalent for the name; equal IDs under different names would need a SHA-256 collision
    for (let j = 0; j < i; j++) if ((out[j].name === out[i].name && out[j].id === out[i].id) || out[j].key === out[i].key) throw new TypeError('a key is listed twice')
  }
  return out
}

// A note signed by Ed25519 keys (type 0x01), given as verifier keys: { ok, text, signers } with the names of the
// keys whose signatures verified, in configuration order.
export function verifyNote (note, ctx) {
  const keys = keyList(typeof ctx === 'object' && ctx !== null ? ctx.keys : undefined, LOG)
  const p = parse(note)
  if (p === undefined) return refuse('note-form')
  const s = signatures(p, keys)
  if (typeof s === 'string') return refuse(s)
  const signers = []
  // Stryker disable next-line EqualityOperator: equivalent; past the keys, s.at gives undefined, which is not >= 0
  for (let k = 0; k < keys.length; k++) if (s.at[k] >= 0) signers[signers.length] = keys[k].name
  return signers.length === 0 ? refuse('unverified') : accept({ text: p.text, signers: freeze(signers) })
}

function checkpointConfig (ctx) {
  if (typeof ctx !== 'object' || ctx === null) throw new TypeError('context must be an object')
  const { origin, log, cosigners, quorum, now, skew } = ctx
  if (typeof origin !== 'string' || origin === '') throw new TypeError('context must hold the log origin')
  // Nor may a cosigner's key be the log's own, under another type: the log alone could then meet the quorum.
  const keys = [vkey(log, LOG), ...keyList(cosigners, COSIGNATURE)]
  for (let i = 1; i < keys.length; i++) if (keys[i].key === keys[0].key) throw new TypeError('a key is listed twice')
  if (!isSafeInteger(quorum) || quorum < 0 || quorum > keys.length - 1) throw new TypeError('quorum must be 0 to the number of cosigners')
  if (!isSafeInteger(now) || now < 0 || !isSafeInteger(skew) || skew < 0) throw new TypeError('context must hold non-negative now and skew')
  return { origin, keys, quorum, now, skew }
}

// A checkpoint signed by its log (Ed25519, type 0x01) and cosigned by at least `quorum` of the configured cosigners
// (timestamped Ed25519, type 0x04): { ok, origin, size, root (hex), times } where `times` are the cosignatures'
// times, ascending, counting only those no later than now + skew. Extension lines are refused.
export function verifyCheckpoint (note, ctx) {
  const c = checkpointConfig(ctx)
  const p = parse(note)
  if (p === undefined) return refuse('note-form')
  const lines = []
  let at = 0
  while (at < p.text.length) {
    const end = apply(indexOf, p.text, ['\n', at]) // found: the text ends with a newline
    lines[lines.length] = apply(slice, p.text, [at, end])
    at = end + 1
  }
  if (lines.length !== 3) return refuse('checkpoint-form')
  const root = fromBase64(lines[2])
  const size = matches(DECIMAL, lines[1]) ? +lines[1] : NaN
  if (lines[0] === '' || !isSafeInteger(size) || root === undefined || root.length !== 32) return refuse('checkpoint-form')
  if (lines[0] !== c.origin) return refuse('origin')
  const s = signatures(p, c.keys)
  if (typeof s === 'string') return refuse(s)
  if (s.at[0] < 0) return refuse('log-signature')
  const times = []
  // Stryker disable next-line EqualityOperator: equivalent; past the keys, s.time gives undefined, which is not <= now
  for (let k = 1; k < c.keys.length; k++) if (s.time[k] <= c.now + c.skew) times[times.length] = s.time[k] // set only if signed
  apply(sort, times, [(a, b) => a - b])
  if (times.length < c.quorum) return refuse('cosigners')
  return accept({ origin: lines[0], size, root: toHex(root), times: freeze(times) })
}

