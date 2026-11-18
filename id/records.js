// The id page's records (SPEC §8), built with the core's own functions: the root record from a new passkey, the W1
// challenge, the assertion object (W0–W6) from what the passkey returns, and a delegation to a worker's key, whose
// fields the page shows (I4) before the passkey signs. Nothing here signs; the passkey does, in the browser.
import { sha256 } from '@noble/hashes/sha2.js'
import { p256 } from '@noble/curves/nist.js'
import { seal, wrap, open } from '../src/envelope.js'
import { membershipState, isMembership, recoveryCommitment, MIN_RECOVERY_WINDOW, MAX_RECOVERY_WINDOW } from '../src/membership.js'
import { checkRootAssertion } from '../src/assertion.js'
import { checkRoot, identityOf, rootIdOf } from '../src/root.js'
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
  // R11: the salts of the recovery cards this passkey gave out, which it needs on the day it recovers someone.
  if (x.salts !== undefined && !(Array.isArray(x.salts) && x.salts.length <= MAX_SALTS && x.salts.every((t) => typeof t === 'string' && ID.test(t)))) return null
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

// SPEC §8: an application sends the person to the page with its request in the fragment, `#muid-request=` and the
// base64url of a JSON object, and is answered in the fragment of its own `return` address. A request only fills the
// page's form: what is signed is reviewed and signed as anything typed there is. The request, with `from` (the
// origin of its return address, to show); null for a fragment that is no request; anything else is refused.
const REQUEST = '#muid-request='
const REQUEST_KEYS = 'agent,aud,days,return,scopes,state,subject,v'
const MAX_REQUEST = 8192
const short = (x) => typeof x === 'string' && x.length >= 1 && x.length <= 64
export function readRequest (fragment) {
  if (typeof fragment !== 'string' || !fragment.startsWith(REQUEST)) return null
  const refused = new Error('that request is not one this page can read')
  let r, to
  try {
    if (fragment.length > MAX_REQUEST) throw refused
    r = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fromB64u(fragment.slice(REQUEST.length))))
    to = new URL(r.return)
  } catch {
    throw refused
  }
  if (Array.isArray(r) || Object.keys(r).sort().join() !== REQUEST_KEYS || r.v !== 1 || !short(r.agent) || typeof r.subject !== 'string' || !ID.test(r.subject) ||
    typeof r.aud !== 'string' || r.aud.length > 2048 || !Array.isArray(r.scopes) || r.scopes.length < 1 || r.scopes.length > 16 || !r.scopes.every(short) ||
    !Number.isSafeInteger(r.days) || r.days < 1 || r.days > 7 || typeof r.state !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(r.state) ||
    // The return address as the browser would go to it, and nothing a reader could mistake: https (http at localhost
    // alone), no name or password, no fragment of its own.
    r.return.length > 2048 || to.href !== r.return || (to.protocol !== 'https:' && !(to.protocol === 'http:' && to.hostname === 'localhost')) ||
    to.username !== '' || to.password !== '' || r.return.includes('#')) throw refused
  return { agent: r.agent, subject: r.subject, aud: r.aud, scopes: [...r.scopes], days: r.days, return: r.return, state: r.state, from: to.origin }
}
// Where the page goes once the request's worker is authorised: the return address, with the hand-off in its fragment.
export const answer = (request, handOff) => request.return + '#muid=' + b64u(new TextEncoder().encode(JSON.stringify({ v: 1, state: request.state, handOff })))

// Decision 3's batched renewal. The page remembers each worker it authorised (what the user entered, never a secret),
// and builds the delegations of up to MAX_BATCH of them again for one assertion (W0 covers at most eight records).
export const MAX_BATCH = 8
export const MAX_WORKERS = 32
// An agent's name outlives its keys, and it has one key at a time: an entry gives way to a newer one of its agent
// that has another key (the key was replaced) or the same audience (the delegation was).
const givesWay = (old, worker) => old.agent === worker.agent && (old.subject !== worker.subject || old.aud === worker.aud)

function workerOf (x) {
  if (x === null || typeof x !== 'object' || Array.isArray(x) || Object.keys(x).length !== 5 ||
    typeof x.agent !== 'string' || typeof x.aud !== 'string' || !Array.isArray(x.scopes) ||
    !x.scopes.every((s) => typeof s === 'string') || !Number.isSafeInteger(x.lifetime) || !checkEd25519Key(x.subject).ok) return undefined
  return { agent: x.agent, subject: x.subject, aud: x.aud, scopes: [...x.scopes], lifetime: x.lifetime }
}

// The list with `worker` last, in place of the older entries that give way to it; the oldest dropped past
// MAX_WORKERS.
export function remember (list, worker) {
  return [...list.filter((w) => !givesWay(w, worker)), worker].slice(-MAX_WORKERS)
}

// The keys remembered for the worker's agent that remembering it would replace, each once.
export function retired (list, worker) {
  return [...new Set(list.filter((w) => w.agent === worker.agent && w.subject !== worker.subject).map((w) => w.subject))]
}

// The workers the page kept in storage, read back as untrusted: only entries of a worker's form, the latest of each
// agent and audience, under the agent's latest key. Their values are checked when a delegation is built from them, as a new one's are.
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
  if (workers.some((w) => workers.some((v) => v.agent === w.agent && v.subject !== w.subject))) throw new Error('an agent is listed with two keys')
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
  // R11: the settled membership's designation (its parties' commitments), and the recovery under notice, or null.
  const recovery = s.recovery === null ? null : { parties: [...s.recovery.parties], threshold: s.recovery.threshold, window: s.recovery.window }
  const recovering = s.recovering === null ? null : { record: s.recovering.record, at: s.recovering.at }
  return { membership: s.membership, epoch: s.epoch, roots: [...s.roots], authority: [...s.authority], pending: s.pending, recovery, recovering }
}

// The membership change that adds the root in `root` (its root record) to the current membership (R1): the next
// epoch, the roots sorted. { body, payload, id, added }; anything R1 or the witness would refuse, refused first.
export function addRoot ({ identity, state, root, rpId }) {
  if (state.pending) throw new Error('a change is already pending: wait for it to settle')
  const r = checkRoot(root, { rpId })
  if (!r.ok) throw new Error(`that is not a root record: ${r.reason}`)
  if (state.roots.includes(r.id)) throw new Error('that passkey is already a root of this identity')
  if (state.roots.length >= 5) throw new Error('an identity has at most 5 roots')
  // R11: a record without `recovery` designates none, so the designation in force is stated again.
  const body = { identity, prev: state.membership, epoch: state.epoch + 1, roots: [...state.roots, r.id].sort(), ...(state.recovery ? { recovery: state.recovery } : {}) }
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
  if (!isMembership(r.body)) throw new Error('that is not a membership change')
  const { identity, prev, epoch, roots, recovery } = r.body
  const body = { identity, prev, epoch, roots: Array.from(roots) }
  // R11: the designation it states is shown with it (I4): a change that leaves it out ends the one in force.
  if (recovery !== undefined) body.recovery = { parties: Array.from(recovery.parties), threshold: recovery.threshold, window: recovery.window }
  return { body, id: r.id, payload }
}

// ---- R11: recovery parties (SPEC §8) ----
export const DEFAULT_RECOVERY_WINDOW = 1_209_600 // 14 days: what the page offers
const MAX_PARTIES = 3
export const MAX_SALTS = 32 // the recovery cards one passkey gives out
const POSSESSION = new TextEncoder().encode('muid-possession\n')
const unhex = (t) => Uint8Array.from(t.match(/../g), (x) => parseInt(x, 16))

// A recovery card: what a party gives whoever would designate it, as one line of text. The party keeps the salt
// too (`kept`: its salts with this one added), since on the day it recovers someone nobody else may have the card.
export const card = (rootText, salt) => JSON.stringify({ root: rootText, salt })
export const newSalt = () => hex(crypto.getRandomValues(new Uint8Array(32)))
// The salts kept with `salt` added, or as they were if they are as many as are kept.
export const kept = (salts = [], salt) => salts.length >= MAX_SALTS ? salts : [...salts, salt]
// A card read back: the party it names (as `party` gives it), or a reason.
export function fromCard (text, rpId) {
  let c
  try {
    c = JSON.parse(text)
  } catch { /* not JSON: nothing is read, and it is refused as anything without a root is */ }
  if (typeof c?.root !== 'string') throw new Error('that is not a recovery card')
  return party(c.root, c.salt, rpId)
}

// How many of `n` parties recover: more than half (R11).
export const majority = (n) => Math.floor(n / 2) + 1

// What a party's passkey signs to show it is held: not the record's id, which signed with the card's salt beside
// it would be a party's signature on that record (R11), but a value under a domain of its own that is no record's id.
export function possessionId (record) {
  if (typeof record !== 'string' || !ID.test(record)) throw new Error('a record id is 64 lowercase hex digits')
  const bytes = new Uint8Array(POSSESSION.length + 32)
  bytes.set(POSSESSION, 0)
  bytes.set(unhex(record), POSSESSION.length)
  return hex(sha256(bytes))
}

// SPEC §8: an identity opened where its passkey is and its page's storage is not (a synced passkey on another
// device, a browser whose data was cleared). The passkey signs the identity's possession value, which is no record's
// id and signs nothing else; the root it belongs to is the one, among the root records the witness holds and the
// roots of the identity's current membership, whose key made that assertion: { text, id, identity }. The assertion is
// then discarded. Nothing is taken on anyone's word: a passkey that is none of the identity's opens nothing.
export function opened ({ identity, roots, state, assertion, rpId, origin, record = possessionId(identity) }) {
  for (const text of roots) {
    const r = checkRoot(text, { rpId })
    if (r.ok && state.roots.includes(r.id) && checkRootAssertion(assertion, { record, rpId, origin, key: r.key }).ok) return { text, id: r.id, identity }
  }
  throw new Error("that passkey is not one of this identity's")
}

// The identities a passkey's assertion may be the first root of, from its signature alone: an ECDSA signature over a
// known message gives its public key up to two candidates, and a root's key gives its id, and a first root's id the
// identity. Nothing is taken from this but where to look: `opened` then requires the witness to hold that root, in
// the identity's current membership, and the assertion to verify under it. (A root added later, by joining, is not
// found this way: its identity is not its own id's.)
export function firstRootIdentities ({ authenticatorData, clientDataJSON, signature }, rpId) {
  const ad = new Uint8Array(authenticatorData)
  const message = new Uint8Array(ad.length + 32)
  message.set(ad)
  message.set(sha256(new Uint8Array(clientDataJSON)), ad.length)
  const digest = sha256(message)
  const out = []
  let sig
  try {
    sig = p256.Signature.fromBytes(new Uint8Array(signature), 'der')
  } catch {
    return out
  }
  for (const bit of [0, 1]) {
    try {
      const id = identityOf(rootIdOf(rpId, hex(sig.addRecoveryBit(bit).recoverPublicKey(digest).toBytes(false))))
      if (!out.includes(id)) out.push(id)
    } catch { /* no key for this bit */ }
  }
  return out
}

// What a party gives whoever would designate it: its root record and a salt it keeps. { root, key, salt,
// commitment }; the commitment is all a designation shows of it.
export function party (rootText, salt, rpId) {
  const r = checkRoot(rootText, { rpId })
  if (!r.ok) throw new Error(`that is not a root record: ${r.reason}`)
  if (typeof salt !== 'string' || !ID.test(salt)) throw new Error('a salt is 64 lowercase hex digits')
  return { root: r.id, key: r.key, salt, commitment: recoveryCommitment(r.id, salt) }
}

// The membership change that designates `parties` (each from `party`) for the current roots: { body, payload, id }.
// Anything R11 or the witness would refuse is refused first; so is a party that is one of the identity's own roots,
// which R11 counts for nothing.
export function designate ({ identity, state, parties, threshold, window }) {
  if (state.pending) throw new Error('a change is already pending: wait for it to settle')
  if (!Array.isArray(parties) || parties.length < 1 || parties.length > MAX_PARTIES) throw new Error(`name 1 to ${MAX_PARTIES} recovery parties`)
  if (parties.some((p) => state.roots.includes(p.root))) throw new Error("a recovery party must not be one of this identity's own passkeys")
  const commitments = parties.map((p) => p.commitment).sort()
  if (new Set(parties.map((p) => p.root)).size !== parties.length) throw new Error('a recovery party is named twice')
  if (!Number.isInteger(threshold) || 2 * threshold <= parties.length || threshold > parties.length) throw new Error('the parties needed must be more than half of those named')
  if (!Number.isInteger(window) || window < MIN_RECOVERY_WINDOW || window > MAX_RECOVERY_WINDOW) throw new Error('the waiting period must be 3 to 90 days')
  const body = { identity, prev: state.membership, epoch: state.epoch + 1, roots: [...state.roots], recovery: { parties: commitments, threshold, window } }
  return { body, ...seal('membership', body) }
}

// The change that ends the designation in force: the same roots, and no `recovery`.
export function undesignate ({ identity, state }) {
  if (state.pending) throw new Error('a change is already pending: wait for it to settle')
  if (state.recovery === null) throw new Error('no recovery parties are designated')
  const body = { identity, prev: state.membership, epoch: state.epoch + 1, roots: [...state.roots] }
  return { body, ...seal('membership', body) }
}

// A party shows it holds its key: an ordinary root assertion covering `record`'s possession value, checked under
// the party's own root record, this rp ID and origin. The assertion is then discarded: it carries no authority, and
// published it would name the party its commitment hides.
export function possession (p, assertion, { record, rpId, origin }) {
  const a = checkRootAssertion(assertion, { record: possessionId(record), rpId, origin, key: p.key })
  if (!a.ok) throw new Error(`the party's passkey did not sign this: ${a.reason}`)
}

// Whether `text`, what a party gave back, shows that `p` holds its passkey for `record`.
export function shows (p, text, ctx) {
  try {
    possession(p, JSON.parse(text), ctx)
    return true
  } catch {
    return false
  }
}

// A change handed to another of the identity's passkeys to co-sign, which may only set or end the designation: the
// current membership's successor with the same roots. As `changeToSign` gives it, or a reason.
export function recoveryChange (payload, { identity, state }) {
  const c = changeToSign(payload)
  if (state.pending) throw new Error('a change is already pending: wait for it to settle')
  if (c.body.identity !== identity || c.body.prev !== state.membership || c.body.epoch !== state.epoch + 1 ||
    JSON.stringify(c.body.roots) !== JSON.stringify(state.roots)) throw new Error("that change does more than set this identity's recovery parties")
  return c
}

// R11, for one who has lost every passkey: the recovery that makes the new passkey in `root` (its root record) the
// identity's only root, stating the designation in force again. { body, payload, id, added }. Its parties sign it
// first; this root after them.
export function recovery ({ identity, state, root, rpId }) {
  if (state.pending) throw new Error('a change is already pending: wait for it to settle')
  if (state.recovery === null) throw new Error('that identity has designated no recovery parties')
  if (state.recovering !== null) throw new Error('a recovery of that identity is already under notice')
  const r = checkRoot(root, { rpId })
  if (!r.ok) throw new Error(`that is not a root record: ${r.reason}`)
  if (state.roots.includes(r.id)) throw new Error('that passkey is already a root of this identity')
  const body = { identity, prev: state.membership, epoch: state.epoch + 1, roots: [r.id], recovery: state.recovery }
  return { body, ...seal('membership', body), added: r.id }
}

// R11, for a party asked to sign a recovery: the request read (as `changeToSign` gives it) with the salt, among
// those this passkey kept, that opens one of the designation's commitments, and the wait; or a reason. `state` is
// the identity's, as the witness gives it; `root` this passkey's root id.
export function rescue (payload, { state, root, salts }) {
  const c = changeToSign(payload)
  if (state.pending || state.recovery === null) throw new Error('that identity has no recovery parties who can act now')
  if (c.body.prev !== state.membership || c.body.epoch !== state.epoch + 1) throw new Error('that request is not for the identity as it now stands')
  if (state.roots.includes(root)) throw new Error("this passkey is one of that identity's own")
  const salt = salts.find((t) => state.recovery.parties.includes(recoveryCommitment(root, t)))
  if (salt === undefined) throw new Error("this passkey is not one of that identity's recovery parties")
  return { ...c, salt, window: state.recovery.window }
}

// Whether `p` (from `party`) is one of the designation's parties: its root id and salt open a commitment there.
export const designated = (recovery, p) => recovery !== null && recovery.parties.includes(p.commitment)

// The root-signed cancel of the recovery under notice (any one root's): { body, payload, id }.
export function cancel ({ identity, state }) {
  if (state.recovering === null) throw new Error('no recovery is under notice')
  const body = { identity, record: state.recovering.record }
  return { body, ...seal('cancel', body) }
}

// When the recovery under notice matures unless cancelled: the notice's time and the designation's window.
export const maturesAt = (state) => state.recovering.at + state.recovery.window

// A party's signature on a recovery: its assertion with the root id and salt that open its commitment (R11).
export const partySigned = (payload, p, assertion) => wrap(payload, { assertion, root: p.root, salt: p.salt })
