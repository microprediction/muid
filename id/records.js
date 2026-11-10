// The id page's records (SPEC §8), built with the core's own functions: the root record from a new passkey, the W1
// challenge, the assertion object (W0–W6) from what the passkey returns, and a delegation to a worker's key, whose
// fields the page shows (I4) before the passkey signs. Nothing here signs; the passkey does, in the browser.
import { sha256 } from '@noble/hashes/sha2.js'
import { seal, wrap, open } from '../src/envelope.js'
import { membershipState } from '../src/membership.js'
import { checkRoot, identityOf } from '../src/root.js'
import { isCanonicalOrigin } from '../src/origin.js'
import { checkEd25519Key } from '../src/ed25519.js'

// A P-256 SubjectPublicKeyInfo (RFC 5480) is this 26-byte header and the 65-byte uncompressed point.
const SPKI_P256 = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
const ASSERT_PREFIX = 'muid/v1/assert\n'
const SCOPE = /^[a-z][a-z0-9_.:-]{0,63}$/
export const MAX_LIFETIME = 604_800 // 7 days: the id page gives machines at most this (decision 3)
const ID = /^[0-9a-f]{64}$/

// What the page kept in storage, read back as untrusted (anything on this origin may have written it): a root of its
// form for this rp ID, its id taken from its own record; otherwise none.
export function storedRoot (x, rpId) {
  if (x === null || typeof x !== 'object' || Array.isArray(x) || typeof x.credential !== 'string' ||
    typeof x.identity !== 'string' || !ID.test(x.identity) || !['undefined', 'boolean'].includes(typeof x.joining) ||
    !['undefined', 'boolean'].includes(typeof x.registered)) return null
  // Whatever x.text is, checkRoot refuses it unless it is a root record's text.
  const r = checkRoot(x.text, { rpId })
  if (!r.ok) return null
  // A co-signature waiting to be sent again is only a joining root's, and its own.
  if (x.cosigned !== undefined && (x.joining !== true || cosignedIdentity(x.cosigned, r.id) === undefined)) return null
  return { ...x, id: r.id }
}

// A co-signature kept to be sent again, as a registration is (an outbox): a membership change that adds `root`,
// signed by it. The identity it joins, or undefined for anything else.
export function cosignedIdentity (text, root) {
  let r
  try {
    r = open(text, 'membership')
  } catch {
    return undefined
  }
  return r.sig.root === root && Array.isArray(r.body.roots) && Array.prototype.includes.call(r.body.roots, root) ? r.body.identity : undefined
}

// A root's fingerprint, shown on both devices when one adds the other's root, for the user to compare before signing
// (Bluetooth pairing's numeric comparison; Signal's safety numbers): 96 bits of the root id, in six groups of four.
export function fingerprint (id) {
  if (typeof id !== 'string' || !ID.test(id)) throw new TypeError('a root id is 64 lowercase hex digits')
  return id.slice(0, 24).match(/.{4}/g).join(' ')
}

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
// Unpadded base64url (RFC 4648 §5), as WebAuthn fields are written (W6).
export function b64u (buf) {
  let s = ''
  for (const x of new Uint8Array(buf)) s += String.fromCharCode(x)
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}
export const fromB64u = (s) => Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0))

// The root record for a new passkey: { text, id, identity }. Only ES256 (alg -7) on P-256 (I6).
export function rootRecord (spki, alg, rpId) {
  if (alg !== -7) throw new Error('the passkey must use ES256 (P-256)')
  const b = new Uint8Array(spki)
  if (b.length !== 91 || hex(b.subarray(0, 26)) !== SPKI_P256) throw new Error('the passkey did not give a P-256 public key')
  const text = wrap(seal('root', { pub: hex(b.subarray(26)), rp_id: rpId }).payload)
  const r = checkRoot(text, { rpId })
  if (!r.ok) throw new Error(`the passkey's key is not usable: ${r.reason}`)
  return { text, id: r.id, identity: identityOf(r.id) }
}

// W1: SHA-256 of the prefix and each covered id followed by a newline, as the bytes the passkey is asked to sign.
export function challenge (covers) {
  return sha256(new TextEncoder().encode(ASSERT_PREFIX + covers.map((id) => id + '\n').join('')))
}

// The assertion object (W6) from a WebAuthn assertion response's three buffers.
export function assertion (covers, { authenticatorData, clientDataJSON, signature }) {
  return { covers: [...covers], authenticator_data: b64u(authenticatorData), client_data_json: b64u(clientDataJSON), signature: b64u(signature) }
}

// A delegation to a worker's Ed25519 key, from `now` for `lifetime` seconds: { body, payload, id }. Scopes are
// sorted and duplicates dropped; anything the verifier would refuse is refused here first, with a reason to show.
export function delegation ({ agent, identity, membership, root, subject, aud, scopes, now, lifetime }) {
  // Decision 13: the light identity the worker is, by a name of a scope's form; its key may change, the name stays.
  if (typeof agent !== 'string' || !SCOPE.test(agent)) throw new Error("the agent's name must be a lower-case name, such as forecaster")
  if (!checkEd25519Key(subject).ok) { // 64 lower-case hex digits, a point on the curve
    throw new Error("the worker's key must be an Ed25519 public key, 64 hex digits")
  }
  if (!isCanonicalOrigin(aud)) throw new Error('the audience must be an origin, such as https://app.example')
  const list = [...new Set(scopes)].sort()
  if (list.length < 1 || list.length > 16 || !list.every((s) => typeof s === 'string' && SCOPE.test(s))) {
    throw new Error('scopes must be 1 to 16 lower-case names')
  }
  if (list.includes('attest')) throw new Error('the attest scope is not granted to a worker') // SPEC §8
  if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > MAX_LIFETIME) throw new Error('the lifetime must be 1 second to 7 days')
  const body = { agent, identity, membership, root, subject, aud, scopes: list, nbf: now, exp: now + lifetime }
  return { body, ...seal('delegation', body) }
}

// Decision 3's batched renewal. The page remembers each worker it authorised (what the user entered, never a secret),
// and builds the delegations of up to MAX_BATCH of them again for one assertion (W0 covers at most eight records).
export const MAX_BATCH = 8
export const MAX_WORKERS = 32
const sameWorker = (a, b) => a.agent === b.agent && a.subject === b.subject

function workerOf (x) {
  if (x === null || typeof x !== 'object' || Array.isArray(x) || Object.keys(x).length !== 5 ||
    typeof x.agent !== 'string' || typeof x.subject !== 'string' || typeof x.aud !== 'string' || !Array.isArray(x.scopes) ||
    !x.scopes.every((s) => typeof s === 'string') || !Number.isSafeInteger(x.lifetime)) return undefined
  return { agent: x.agent, subject: x.subject, aud: x.aud, scopes: [...x.scopes], lifetime: x.lifetime }
}

// The list with `worker` last, in place of an older entry of the same agent and key; the oldest dropped past
// MAX_WORKERS.
export function remember (list, worker) {
  return [...list.filter((w) => !sameWorker(w, worker)), worker].slice(-MAX_WORKERS)
}

// The workers the page kept in storage, read back as untrusted: only entries of a worker's form, the latest of each
// agent and key. Their values are checked when a delegation is built from them, as a new one's are.
export function storedWorkers (x) {
  if (!Array.isArray(x)) return []
  let out = []
  for (const e of x) {
    const w = workerOf(e)
    if (w !== undefined) out = remember(out, w)
  }
  return out
}

// Each worker's delegation built again from `now` under the current membership, and their ids, sorted, for the one
// assertion that signs them all: { delegations, covers }.
export function renewals (workers, { identity, membership, root, now }) {
  if (workers.length < 1 || workers.length > MAX_BATCH) throw new Error(`renew 1 to ${MAX_BATCH} workers at once`)
  const delegations = workers.map((w) => delegation({ ...w, identity, membership, root, now }))
  const covers = delegations.map((d) => d.id).sort()
  if (new Set(covers).size !== covers.length) throw new Error('a worker is listed twice')
  return { delegations, covers }
}

// What the page hands the worker: the payload and the root's assertion. The worker adds its own consent (D6).
export const handOff = (payload, root) => JSON.stringify({ payload, root })

// The identity's current membership, from the records the witness holds, by the core's own membershipState: the
// effective membership's id, epoch and roots, the roots with authority (R6), and whether a change is pending.
export function currentMembership (records, ctx) {
  const s = membershipState(records, ctx)
  if (!s.ok) throw new Error('the witness holds no record of this identity')
  if (s.dead) throw new Error('this identity has ended')
  return { membership: s.membership, epoch: s.epoch, roots: [...s.roots], authority: [...s.authority], pending: s.pending }
}

// The membership change that adds the root in `root` (its root record) to the current membership (R1): the next
// epoch, the roots sorted. { body, payload, id, added }; anything R1 or the witness would refuse, refused first.
export function addRoot ({ identity, state, root, rpId }) {
  if (state.pending) throw new Error('a change is already pending: wait for it to settle')
  const r = checkRoot(root, { rpId })
  if (!r.ok) throw new Error(`that is not a root record: ${r.reason}`)
  if (state.roots.includes(r.id)) throw new Error('that passkey is already a root of this identity')
  if (state.roots.length >= 5) throw new Error('an identity has at most 5 roots')
  const body = { identity, prev: state.membership, epoch: state.epoch + 1, roots: [...state.roots, r.id].sort() }
  return { body, ...seal('membership', body), added: r.id }
}

// A root-signed record's envelope: the payload, signed by one root's assertion (R1–R5's `sig = { root, assertion }`).
export const rootSigned = (payload, root, assertion) => wrap(payload, { root, assertion })

// A membership change handed over to co-sign: its body (to show, I4), id (to sign) and payload; else a reason.
export function changeToSign (payload) {
  let r
  try {
    r = open(wrap(payload, {}), 'membership')
  } catch {
    throw new Error('that is not a membership change')
  }
  const { identity, prev, epoch, roots } = r.body
  if (!Array.isArray(roots)) throw new Error('that is not a membership change')
  return { body: { identity, prev, epoch, roots: Array.from(roots) }, id: r.id, payload }
}
