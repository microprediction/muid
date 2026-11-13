// Membership state (SPEC §5 R1–R8, R11): from an identity's records, its current membership, as model/settled.mjs
// specifies. Each record is verified on its own; one that does not verify carries no authority and is ignored.
import { sha256 } from '@noble/hashes/sha2.js'
import { open } from './envelope.js'
import { checkRootAssertion } from './assertion.js'
import { checkEd25519 } from './ed25519.js'
import { checkRoot, identityOf } from './root.js'
import { readWitnessKeys, isWitnessSig, witnessReason } from './attestation.js'
import { refuse, accept, fromHex, toHex } from './bytes.js'

const { apply } = Reflect
const { freeze, create } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { includes, splice } = Array.prototype

const ID = /^[0-9a-f]{64}$/
const MAX_ROOTS = 5
// R11: a membership designates at most this many recovery parties; a recovery waits under notice for the window it
// states, between these (3 and 90 days, in seconds).
const MAX_PARTIES = 3
export const MIN_RECOVERY_WINDOW = 259_200
export const MAX_RECOVERY_WINDOW = 7_776_000
// Each list of records is at most this long, so the work a caller can cause is bounded.
export const MAX_RECORDS = 256
export const MAX_REVOKED = 64 // R9
const isId = (x) => typeof x === 'string' && apply(exec, ID, [x]) !== null
// An integer; a negative `at` or `epoch` fails the witness window or the epoch check (R1) after it.
const isInteger = (x) => isSafeInteger(x)
const has = (list, x) => apply(includes, list, [x])

// §4 residual: code that patches built-ins the crypto library uses (noble does not capture them) could make every
// valid signature fail, and every record would then be ignored, leaving the first root alone. So each call first
// checks a known answer on each curve, as FIPS 140 modules self-test before use; a wrong one refuses the call
// (self-test), never ignores records. Under a domain of its own: nothing it signs is a record. (No single patched
// built-in makes the library accept an invalid signature, tests/patched/P1, so no known invalid answer is checked.)
const KAT = freeze({
  assertion: freeze({ covers: freeze(['5e'.repeat(32)]), authenticator_data: '_U6FGpYnHCmkyFsGmDRfk4qCxAphz7r_xdXj1gc0uk0FAAAAAA',
    client_data_json: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNnMtVFRZNU9uSmZhQzNNVVNIUW1BdDh5MEFZUnUwOHRVWXZCQkxGS1U2YyIsIm9yaWdpbiI6Imh0dHBzOi8vc2VsZi10ZXN0LmludmFsaWQiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
    signature: 'MEQCIBO9E2nYAD7tqS1O8jJEK85RYgSYfKt2gJa9ZEkQX8z7AiBnbdSBvs-NzaWC_DvVQWBWsAw23HfqDWhBWeWZTQL02w' }),
  ctx: freeze({ record: '5e'.repeat(32), rpId: 'self-test.invalid', origin: 'https://self-test.invalid',
    key: '0483b1be1851edbe767622396bd3d0d6199279c9f6f82eadbca4cd1c2ceb4497c937e0664d65dab66f53ede17e3f7f98ea9aed97b48c4a953cac66b36379299fad' }),
  edKey: 'c335bddf9858533d4dcc5182d85804da88075b9b862b64fb5ee16ea604a6c64a',
  edSig: '3fe07f6135b59432071044525c5e6f72de0dd0366e583ee2137eab2cd90e0a5ed7eeb8eaf624b5cf719fe3da7ac0c44d98172a2c05d7b95aab2ca93e1402d608',
})
const KAT_MESSAGE = new TextEncoder().encode('muid self-test\n') // made at load
const PARTY = new TextEncoder().encode('muid-recovery\n') // made at load

// R11: the commitment a designation holds for a recovery party: the hash of its root id and a salt, both ids' worth
// of hex, under a domain of its own.
export function recoveryCommitment (root, salt) {
  if (!isId(root) || !isId(salt)) throw new TypeError('root and salt must be 32 bytes of lowercase hex')
  const bytes = new Uint8Array(PARTY.length + 64)
  bytes.set(PARTY, 0)
  bytes.set(fromHex(root), PARTY.length)
  bytes.set(fromHex(salt), PARTY.length + 32)
  return toHex(sha256(bytes))
}
const selfTest = () => checkRootAssertion(KAT.assertion, KAT.ctx).ok === true && checkEd25519(KAT.edSig, KAT_MESSAGE, KAT.edKey).ok === true

// No keys but these, in canonical order; a missing key fails its own field check.
function onlyKeys (o, keys) {
  let i = 0
  for (const k in o) if (k !== keys[i++]) return false
  return true
}

function opened (text, type) {
  try {
    return open(text, type)
  } catch { /* does not verify: ignored */ }
  return undefined
}

function readContext (ctx) {
  if (typeof ctx !== 'object' || ctx === null) return undefined
  const { identity, rpId, origin, witnessKeys } = ctx
  const keys = readWitnessKeys(witnessKeys)
  if (!isId(identity) || typeof rpId !== 'string' || typeof origin !== 'string' || keys === undefined) return undefined
  return { identity, rpId, origin, keys }
}

// Tables are null-prototype objects keyed by id, read with index loops, never Map or Set: no built-in a page could
// patch after load stands between a record and its count (§4 residual, tests/patched/P2-membership).
const table = () => create(null)

// A root-signed record of `type` whose body passes `bodyOk`: { id, body, signer, salt }, or undefined. A signer
// already counted for that record (in `counted`, as id + signer) is not verified again. With `party` (R11), the
// signature may open a recovery party's commitment with its salt, and is counted apart from the same root's plain
// signature, so that neither hides the other in whatever order they come.
function rootSigned (text, type, bodyOk, ctx, rootKeys, counted, party = false) {
  const r = opened(text, type)
  if (r === undefined || !bodyOk(r.body)) return undefined
  const salt = party ? r.sig.salt : undefined
  if (!onlyKeys(r.sig, salt === undefined ? ['assertion', 'root'] : ['assertion', 'root', 'salt']) || (salt !== undefined && !isId(salt))) return undefined
  const key = isId(r.sig.root) ? rootKeys[r.sig.root] : undefined
  const once = r.id + r.sig.root + (salt ?? '')
  if (key === undefined || counted[once] === true) return undefined
  const a = checkRootAssertion(r.sig.assertion, { record: r.id, rpId: ctx.rpId, origin: ctx.origin, key })
  if (!a.ok) return undefined
  counted[once] = true
  return { id: r.id, body: r.body, signer: r.sig.root, salt }
}

// A witness-signed record of `type`, its key in window at the record's own `at`: its body, or undefined.
function witnessSigned (text, type, bodyOk, ctx) {
  const r = opened(text, type)
  if (r === undefined || !bodyOk(r.body) || !isWitnessSig(r.sig)) return undefined
  // An instant: the key's half-open window must hold [at, at + 1).
  return witnessReason(r.sig, r.payload, ctx.keys, r.body.at, r.body.at + 1) === undefined ? r.body : undefined
}

function rootsOk (roots) {
  if (!isArray(roots) || roots.length < 1 || roots.length > MAX_ROOTS) return false
  for (let i = 0; i < roots.length; i++) {
    if (!isId(roots[i]) || (i > 0 && !(roots[i - 1] < roots[i]))) return false
  }
  return true
}

// R11: a designation of recovery parties: 1–3 commitments, strictly ascending, how many of them a recovery needs
// (a majority), and how long it waits under notice.
function recoveryOk (x) {
  if (typeof x !== 'object' || x === null || isArray(x) || !onlyKeys(x, ['parties', 'threshold', 'window'])) return false
  const { parties, threshold, window } = x
  if (!isArray(parties) || parties.length < 1 || parties.length > MAX_PARTIES) return false
  for (let i = 0; i < parties.length; i++) {
    if (!isId(parties[i]) || (i > 0 && !(parties[i - 1] < parties[i]))) return false
  }
  // A majority of the parties, as guardians' thresholds are: one of several is never enough.
  return isInteger(threshold) && 2 * threshold > parties.length && threshold <= parties.length &&
    isInteger(window) && window >= MIN_RECOVERY_WINDOW && window <= MAX_RECOVERY_WINDOW
}

// Whether `b` is a membership record's body (R1; R11's `recovery` is there or not, never null). The witness admits
// by it, so that it holds no record verifiers would ignore for its form.
export const isMembership = (b) => onlyKeys(b, b.recovery === undefined ? ['epoch', 'identity', 'prev', 'roots'] : ['epoch', 'identity', 'prev', 'recovery', 'roots']) &&
  isInteger(b.epoch) && isId(b.prev) && rootsOk(b.roots) && (b.recovery === undefined || recoveryOk(b.recovery))

// R11: a recovery of `cur`: enough of its designated parties signed, each opening its commitment and none a root of
// `cur`, and every added root signed. One party counts once, whatever it opened.
function recoveryOf (cur, p) {
  if (cur.recovery === undefined) return false
  const parties = cur.recovery.parties
  const seen = []
  for (let i = 0; i < parties.length; i++) {
    const root = p.opened[parties[i]]
    if (root !== undefined && !has(cur.roots, root) && !has(seen, root)) seen[seen.length] = root
  }
  if (seen.length < cur.recovery.threshold) return false
  return addedSigned(cur, p)
}

function addedSigned (cur, p) {
  for (let i = 0; i < p.body.roots.length; i++) {
    const r = p.body.roots[i]
    if (!has(cur.roots, r) && p.signers[r] !== true) return false
  }
  return true
}

// R1: a strict majority of the previous roots signed, and every added root. R11: or a recovery of the previous
// membership that the witness has said matured.
function validNext (cur, p, matured) {
  if (p.body.epoch !== cur.epoch + 1) return false
  if (matured && recoveryOf(cur, p)) return true
  let yes = 0
  // Stryker disable next-line EqualityOperator: equivalent; one more step looks up undefined, never a signer
  for (let i = 0; i < cur.roots.length; i++) if (p.signers[cur.roots[i]] === true) yes++
  if (2 * yes <= cur.roots.length) return false
  return addedSigned(cur, p)
}

// A caller's list, its length read once and capped (refused as records by the caller).
function list (records, key) {
  const x = records[key]
  // Stryker disable next-line ArrayDeclaration: equivalent; a stray element is not a record and is ignored
  if (!isArray(x)) return []
  const n = x.length // read once: a Proxy may report any value, or another each time
  if (!(isSafeInteger(n) && n >= 0 && n <= MAX_RECORDS)) throw new RangeError()
  return copy(x, n)
}

// Calls f on each text of a caller's list (see list).
function each (records, key, f) {
  const texts = list(records, key)
  // Stryker disable next-line EqualityOperator: equivalent; one more step opens undefined, which is ignored
  for (let i = 0; i < texts.length; i++) f(texts[i])
}

// Index loops only: decoded arrays have no prototype, and a caller's array could have a replaced iterator.
function copy (a, n = a.length) {
  // Stryker disable next-line ArrayDeclaration: equivalent; every index is assigned before it is read
  const out = []
  // Stryker disable next-line EqualityOperator: equivalent; one more step copies undefined, which is ignored
  for (let i = 0; i < n; i++) out[i] = a[i]
  return out
}

function read (records, ctx) {
  const rootKeys = table()
  const rootIds = [] // in the order given; a repeated root gives its own id and key again, which changes nothing
  each(records, 'roots', (t) => {
    const r = checkRoot(t, { rpId: ctx.rpId })
    if (r.ok) { rootKeys[r.id] = r.key; rootIds[rootIds.length] = r.id }
  })
  const mine = (b) => b.identity === ctx.identity
  const counted = table()
  const memberships = table()
  const proposals = [] // the memberships, in the order first seen
  each(records, 'memberships', (t) => {
    const m = rootSigned(t, 'membership', (b) => isMembership(b) && mine(b), ctx, rootKeys, counted, true)
    if (m === undefined) return
    if (memberships[m.id] === undefined) proposals[proposals.length] = memberships[m.id] = { id: m.id, body: m.body, signers: table(), opened: table() }
    memberships[m.id].signers[m.signer] = true
    // R11: a party's signature opens its commitment; which membership designated it is decided where it is used.
    if (m.salt !== undefined) memberships[m.id].opened[recoveryCommitment(m.signer, m.salt)] = m.signer
  })
  const contests = table()
  each(records, 'contests', (t) => {
    const c = rootSigned(t, 'contest', (b) => onlyKeys(b, ['identity', 'record']) && mine(b) && isId(b.record), ctx, rootKeys, counted)
    if (c === undefined) return
    if (contests[c.body.record] === undefined) contests[c.body.record] = { id: c.id, signers: table() }
    contests[c.body.record].signers[c.signer] = true
  })
  // Stryker disable next-line ArrayDeclaration: equivalent; a stray element names no membership
  const freezes = []
  each(records, 'freezes', (t) => {
    const f = rootSigned(t, 'freeze', (b) => onlyKeys(b, ['identity', 'membership']) && mine(b) && isId(b.membership), ctx,
      rootKeys, counted)
    if (f !== undefined) freezes[freezes.length] = { membership: f.body.membership, signer: f.signer }
  })
  const anchored = table()
  each(records, 'anchors', (t) => {
    const a = witnessSigned(t, 'anchor', (b) => onlyKeys(b, ['at', 'identity', 'record']) && mine(b) && isInteger(b.at) &&
      isId(b.record), ctx)
    if (a !== undefined) anchored[a.record] = true
  })
  const settled = table() // prev -> the distinct outcomes the witness settled it with, in a list
  each(records, 'settlements', (t) => {
    const s = witnessSigned(t, 'settlement', (b) => onlyKeys(b, ['at', 'identity', 'outcome', 'prev']) && mine(b) &&
      isInteger(b.at) && isId(b.prev) && (b.outcome === 'contested' || isId(b.outcome)), ctx)
    if (s === undefined) return
    if (settled[s.prev] === undefined) settled[s.prev] = []
    if (!has(settled[s.prev], s.outcome)) settled[s.prev][settled[s.prev].length] = s.outcome
  })
  // R11: the witness's statements about recoveries, each { at, identity, record }.
  const stated = (key, type, f) => each(records, key, (t) => {
    const s = witnessSigned(t, type, (b) => onlyKeys(b, ['at', 'identity', 'record']) && mine(b) && isInteger(b.at) && isId(b.record), ctx)
    if (s !== undefined) f(s)
  })
  const notices = []
  stated('notices', 'notice', (s) => { notices[notices.length] = s })
  const cancelled = table()
  stated('cancelled', 'cancelled', (s) => { cancelled[s.record] = true })
  const matured = table()
  stated('matured', 'matured', (s) => { matured[s.record] = true })
  return { rootKeys, rootIds, memberships, proposals, contests, freezes, anchored, settled, notices, cancelled, matured }
}

// R2–R7, as model/settled.mjs evaluates them.
function evaluate (first, ctx, r) {
  let cur = { id: ctx.identity, epoch: 1, roots: [first], recovery: undefined }
  const of = (p) => ({ id: p.id, epoch: p.body.epoch, roots: p.body.roots, recovery: p.body.recovery })
  let pending
  for (;;) {
    const outcomes = r.settled[cur.id]
    if (outcomes !== undefined) {
      if (outcomes.length > 1 || outcomes[0] === 'contested') return accept({ dead: true })
      const next = r.memberships[outcomes[0]]
      if (next === undefined || next.body.prev !== cur.id || !validNext(cur, next, r.matured[next.id] === true)) break // stale: not held
      cur = of(next)
      continue
    }
    const candidates = []
    for (let i = 0; i < r.proposals.length; i++) {
      const p = r.proposals[i]
      if (p.body.prev === cur.id && r.anchored[p.id] === true && validNext(cur, p, r.matured[p.id] === true)) candidates[candidates.length] = p
    }
    if (candidates.length > 1) return accept({ dead: true })
    if (candidates.length === 1) {
      const c = r.contests[candidates[0].id]
      if (c !== undefined && r.anchored[c.id] === true) {
        let yes = 0
        // Stryker disable next-line EqualityOperator: equivalent; one more step looks up undefined, never a signer
        for (let i = 0; i < cur.roots.length; i++) if (c.signers[cur.roots[i]] === true) yes++
        if (2 * yes > cur.roots.length) return accept({ dead: true })
      }
      pending = of(candidates[0])
    }
    break
  }
  const m = pending ?? cur
  const authority = []
  for (let i = 0; i < m.roots.length; i++) if (!pending || has(cur.roots, m.roots[i])) authority[authority.length] = m.roots[i]
  const frozenBy = (x) => {
    for (let i = 0; i < r.freezes.length; i++) if (r.freezes[i].membership === x.id && has(x.roots, r.freezes[i].signer)) return true
    return false
  }
  // R11: the recovery of the settled membership under notice: one the witness gave notice of and has not said was
  // cancelled, and that is not anchored. Of several (a witness that lies), the latest notice, then the least id.
  let notice
  for (let i = 0; i < r.notices.length; i++) {
    const n = r.notices[i]
    const p = r.memberships[n.record]
    if (p === undefined || p.body.prev !== cur.id || r.cancelled[n.record] === true || r.anchored[n.record] === true) continue
    if (notice === undefined || n.at > notice.at || (n.at === notice.at && n.record < notice.record)) notice = n
  }
  const d = cur.recovery
  return accept({
    dead: false,
    identity: ctx.identity,
    membership: m.id,
    settled: cur.id,
    epoch: m.epoch,
    roots: freeze(copy(m.roots)),
    pending: pending !== undefined,
    authority: freeze(authority),
    frozen: frozenBy(m) || frozenBy(cur), // cur is m unless a successor is pending (R2)
    // The settled membership's designation, whose parties may ask for a recovery, and the one under notice.
    recovery: d === undefined ? null : freeze({ parties: freeze(copy(d.parties)), threshold: d.threshold, window: d.window }),
    recovering: notice === undefined ? null : freeze({ record: notice.record, at: notice.at }),
  })
}

export function membershipState (records, context) {
  const ctx = readContext(context)
  if (ctx === undefined) throw new TypeError('context must hold identity, rpId, origin and witnessKeys')
  if (!selfTest()) return refuse('self-test')
  let r
  try {
    r = read(typeof records === 'object' && records !== null ? records : {}, ctx)
  } catch {
    return refuse('records')
  }
  for (let i = 0; i < r.rootIds.length; i++) if (identityOf(r.rootIds[i]) === ctx.identity) return evaluate(r.rootIds[i], ctx, r)
  return refuse('unknown-identity')
}

// R9: the body of the head a witness signs for a state at time `at`: the settled epoch, the settled membership then the
// pending one, the roots with authority, and the revocations it holds for the identity (record ids or subject keys).
// None for a dead or frozen identity, a refusal, a state in which no root has authority, or revocations that are not
// at most 64 ids.
export function headOf (state, at, revoked = []) {
  if (!state.ok || state.dead || state.frozen || state.authority.length === 0 || !isInteger(at) || at < 0 ||
    !isArray(revoked)) return undefined
  // Distinct ids, sorted by insertion (no built-in sort to patch), at most 64: reading stops at the 65th.
  const list = []
  const n = revoked.length // read once, and an array length: a Proxy may report any value, or another each time
  if (!(isInteger(n) && n >= 0 && n < 2 ** 32)) return undefined
  for (let i = 0; i < n; i++) {
    const x = revoked[i]
    if (!isId(x)) return undefined
    let j = list.length
    while (list[j - 1] > x) j-- // list[-1] is undefined, which is never greater
    if (list[j - 1] !== x) apply(splice, list, [j, 0, x])
    if (list.length > MAX_REVOKED) return undefined
  }
  const memberships = state.pending ? [state.settled, state.membership] : [state.settled]
  // The settled epoch: a pending successor's is one more (R1). R11: a recovery under notice is in every head.
  const body = { identity: state.identity, epoch: state.pending ? state.epoch - 1 : state.epoch,
    memberships: freeze(memberships), authority: state.authority, revoked: freeze(list), at }
  if (typeof state.recovering === 'object' && state.recovering !== null) body.recovering = state.recovering
  return freeze(body)
}
