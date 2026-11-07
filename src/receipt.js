// Receipts (SPEC §6 C2, proposal): a service's signed statement that it accepted a claim, logged in a transparency
// log, so the claim stays attributable after its delegation expires. A receipt is the service's statement, trusted
// as far as the caller trusts that service; the cosigned checkpoint bounds, from outside it, when the receipt existed.
import { open, signedBytes, EnvelopeError } from './envelope.js'
import { checkEd25519 } from './ed25519.js'
import { isCanonicalOrigin } from './origin.js'
import { verifyCheckpoint } from './note.js'
import { verifyInclusion, leafHash } from './merkle.js'
import { fromHex, refuse, accept } from './bytes.js'
import { isHex, isTime, onlyKeys } from './attestation.js'

const { apply } = Reflect
const { freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { isRefusal } = EnvelopeError
const encodeText = TextEncoder.prototype.encode
const UTF8 = new TextEncoder()

const BODY_KEYS = freeze(['at', 'claim', 'delegation', 'identity', 'service'])
const SIG_KEYS = freeze(['service', 'signature'])
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/

function readContext (ctx) {
  if (typeof ctx !== 'object' || ctx === null) throw new TypeError('context must be an object')
  const { services, log, now, skew } = ctx
  if (!isArray(services)) throw new TypeError('context must hold the pinned services')
  // Stryker disable next-line ArrayDeclaration: equivalent; every element is assigned below
  const pinned = []
  const n = services.length // read once, and an array length
  if (!(isSafeInteger(n) && n >= 0 && n < 2 ** 32)) throw new TypeError('context must hold the pinned services')
  for (let i = 0; i < n; i++) {
    const { origin, key, nbf, exp } = { ...services[i] } // null and primitives give no fields, and fail below
    if (!isCanonicalOrigin(origin) || !isHex(HEX64, key) || !isTime(nbf) || !isTime(exp)) throw new TypeError('malformed entry in the pinned services')
    pinned[i] = { origin, key, nbf, exp }
  }
  if (typeof log !== 'object' || log === null) throw new TypeError('context must hold the log configuration')
  const { origin, log: key, cosigners, quorum } = log // each read once
  const checkpoint = { origin, log: key, cosigners, quorum, now, skew }
  // Stryker disable next-line StringLiteral: equivalent; any note serves, since only the configuration is checked
  verifyCheckpoint('', checkpoint) // throws for a malformed configuration
  if (quorum < 1) throw new TypeError('a receipt needs at least one cosigner: its time must come from outside the service')
  return { pinned, checkpoint, quorum, now, skew }
}

// { receipt, checkpoint, proof, index, claim? }: the receipt's envelope text, a checkpoint of the log holding it, the
// inclusion proof of its entry at index, and optionally the claim it names.
export function verifyReceipt (given, ctx) {
  if (typeof given !== 'object' || given === null) throw new TypeError('given must be an object')
  const c = readContext(ctx)
  const { receipt, checkpoint, proof, index, claim } = given
  let r
  try {
    r = open(receipt, 'receipt')
  } catch (e) {
    // Anything but a refusal can only come from built-ins patched in the page (§4 residual): fail closed.
    return refuse(isRefusal(e) ? e.reason : 'envelope-encoding')
  }
  const b = r.body
  const sig = r.sig
  if (!onlyKeys(b, BODY_KEYS) || !isHex(HEX64, b.identity) || !isHex(HEX64, b.delegation) || !isHex(HEX64, b.claim) ||
    !isCanonicalOrigin(b.service) || !isTime(b.at) || !onlyKeys(sig, SIG_KEYS) || !isHex(HEX128, sig.signature) ||
    !isHex(HEX64, sig.service)) return refuse('receipt-shape')
  // The latest expiry among the windows pinned for this origin and key that hold `at` (each [nbf, exp), as A1's and
  // D1's are); none means unpinned, refused
  // before the signature is tried (keys are named, never found by trying, as A4).
  let exp = -1
  for (let i = 0; i < c.pinned.length; i++) {
    const s = c.pinned[i]
    // Stryker disable next-line EqualityOperator: equivalent for s.exp > exp; an equal expiry gives the same value
    if (s.origin === b.service && s.key === sig.service && s.nbf <= b.at && b.at < s.exp && s.exp > exp) exp = s.exp
  }
  // Stryker disable next-line EqualityOperator: equivalent; a window holding `at` ends after it, so exp is never 0
  if (exp < 0) return refuse('service')
  const k = checkEd25519(sig.signature, signedBytes(r.payload), sig.service)
  if (!k.ok) return k
  const cp = verifyCheckpoint(checkpoint, c.checkpoint)
  if (!cp.ok) return refuse('checkpoint')
  const entry = leafHash(apply(encodeText, UTF8, [receipt]))
  if (!verifyInclusion({ leafHash: entry, index, size: cp.size, proof, root: fromHex(cp.root) })) return refuse('inclusion')
  const existedBy = cp.times[c.quorum - 1] // the quorum-th earliest: unless the quorum lies, logged by then
  if (b.at > existedBy + c.skew || b.at > c.now + c.skew) return refuse('receipt-time')
  // That window also holds, within skew, the time the receipt was logged by: a retired key cannot backdate.
  if (existedBy >= exp + c.skew) return refuse('service')
  if (claim !== undefined) {
    let named
    try {
      named = open(claim, 'claim')
    } catch {
      return refuse('claim')
    }
    if (named.id !== b.claim || named.body.delegation !== b.delegation) return refuse('claim')
  }
  return accept({ service: b.service, identity: b.identity, delegation: b.delegation, claim: b.claim, at: b.at, existedBy })
}
