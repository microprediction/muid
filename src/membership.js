// Membership state (SPEC §5 R1–R8): from an identity's records, its current membership, as model/settled.mjs
// specifies. Each record is verified on its own; one that does not verify carries no authority and is ignored.
import { open } from './envelope.js'
import { checkRootAssertion } from './assertion.js'
import { checkRoot, identityOf } from './root.js'
import { readWitnessKeys, isWitnessSig, witnessReason } from './attestation.js'
import { refuse, accept } from './bytes.js'

const { apply } = Reflect
const { freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { includes, splice } = Array.prototype

const ID = /^[0-9a-f]{64}$/
const MAX_ROOTS = 5
// Each list of records is at most this long, so the work a caller can cause is bounded.
export const MAX_RECORDS = 256
export const MAX_REVOKED = 64 // R9
const isId = (x) => typeof x === 'string' && apply(exec, ID, [x]) !== null
// An integer; a negative `at` or `epoch` fails the witness window or the epoch check (R1) after it.
const isInteger = (x) => isSafeInteger(x)
const has = (list, x) => apply(includes, list, [x])

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

// A root-signed record of `type` whose body passes `bodyOk`: { id, body, signer }, or undefined. A signer already
// counted for that record (in `counted`, as id + signer) is not verified again.
function rootSigned (text, type, bodyOk, ctx, rootKeys, counted) {
  const r = opened(text, type)
  if (r === undefined || !bodyOk(r.body) || !onlyKeys(r.sig, ['assertion', 'root'])) return undefined
  const key = rootKeys.get(r.sig.root)
  if (key === undefined || counted.has(r.id + r.sig.root)) return undefined
  const a = checkRootAssertion(r.sig.assertion, { record: r.id, rpId: ctx.rpId, origin: ctx.origin, key })
  if (!a.ok) return undefined
  counted.add(r.id + r.sig.root)
  return { id: r.id, body: r.body, signer: r.sig.root }
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

// R1: a strict majority of the previous roots signed, and every added root.
function validNext (cur, p) {
  if (p.body.epoch !== cur.epoch + 1) return false
  let yes = 0
  // Stryker disable next-line EqualityOperator: equivalent; one more step looks up undefined, never a signer
  for (let i = 0; i < cur.roots.length; i++) if (p.signers.has(cur.roots[i])) yes++
  if (2 * yes <= cur.roots.length) return false
  for (let i = 0; i < p.body.roots.length; i++) {
    const r = p.body.roots[i]
    if (!has(cur.roots, r) && !p.signers.has(r)) return false
  }
  return true
}

// A caller's list, its length read once and capped (refused as records by the caller).
function list (records, key) {
  const x = records[key]
  // Stryker disable next-line ArrayDeclaration: equivalent; a stray element is not a record and is ignored
  if (!isArray(x)) return []
  const n = x.length
  if (n > MAX_RECORDS) throw new RangeError()
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
  const rootKeys = new Map()
  each(records, 'roots', (t) => {
    const r = checkRoot(t, { rpId: ctx.rpId })
    if (r.ok) rootKeys.set(r.id, r.key)
  })
  const mine = (b) => b.identity === ctx.identity
  const counted = new Set()
  const memberships = new Map()
  each(records, 'memberships', (t) => {
    const m = rootSigned(t, 'membership', (b) => onlyKeys(b, ['epoch', 'identity', 'prev', 'roots']) && mine(b) &&
      isInteger(b.epoch) && isId(b.prev) && rootsOk(b.roots), ctx, rootKeys, counted)
    if (m === undefined) return
    if (!memberships.has(m.id)) memberships.set(m.id, { id: m.id, body: m.body, signers: new Set() })
    memberships.get(m.id).signers.add(m.signer)
  })
  const contests = new Map()
  each(records, 'contests', (t) => {
    const c = rootSigned(t, 'contest', (b) => onlyKeys(b, ['identity', 'record']) && mine(b) && isId(b.record), ctx, rootKeys, counted)
    if (c === undefined) return
    if (!contests.has(c.body.record)) contests.set(c.body.record, { id: c.id, signers: new Set() })
    contests.get(c.body.record).signers.add(c.signer)
  })
  // Stryker disable next-line ArrayDeclaration: equivalent; a stray element names no membership
  const freezes = []
  each(records, 'freezes', (t) => {
    const f = rootSigned(t, 'freeze', (b) => onlyKeys(b, ['identity', 'membership']) && mine(b) && isId(b.membership), ctx,
      rootKeys, counted)
    if (f !== undefined) freezes[freezes.length] = { membership: f.body.membership, signer: f.signer }
  })
  const anchored = new Set()
  each(records, 'anchors', (t) => {
    const a = witnessSigned(t, 'anchor', (b) => onlyKeys(b, ['at', 'identity', 'record']) && mine(b) && isInteger(b.at) &&
      isId(b.record), ctx)
    if (a !== undefined) anchored.add(a.record)
  })
  const settled = new Map()
  each(records, 'settlements', (t) => {
    const s = witnessSigned(t, 'settlement', (b) => onlyKeys(b, ['at', 'identity', 'outcome', 'prev']) && mine(b) &&
      isInteger(b.at) && isId(b.prev) && (b.outcome === 'contested' || isId(b.outcome)), ctx)
    if (s === undefined) return
    if (!settled.has(s.prev)) settled.set(s.prev, new Set())
    settled.get(s.prev).add(s.outcome)
  })
  return { rootKeys, memberships, contests, freezes, anchored, settled }
}

// R2–R7, as model/settled.mjs evaluates them.
function evaluate (first, ctx, r) {
  let cur = { id: ctx.identity, epoch: 1, roots: [first] }
  let pending
  for (;;) {
    const outcomes = r.settled.get(cur.id)
    if (outcomes !== undefined) {
      if (outcomes.size > 1 || outcomes.has('contested')) return accept({ dead: true })
      const [outcome] = outcomes
      const next = r.memberships.get(outcome)
      if (next === undefined || next.body.prev !== cur.id || !validNext(cur, next)) break // stale: not held
      cur = { id: next.id, epoch: next.body.epoch, roots: next.body.roots }
      continue
    }
    const candidates = []
    for (const p of r.memberships.values()) {
      if (p.body.prev === cur.id && r.anchored.has(p.id) && validNext(cur, p)) candidates[candidates.length] = p
    }
    if (candidates.length > 1) return accept({ dead: true })
    if (candidates.length === 1) {
      const c = r.contests.get(candidates[0].id)
      if (c !== undefined && r.anchored.has(c.id)) {
        let yes = 0
        // Stryker disable next-line EqualityOperator: equivalent; one more step looks up undefined, never a signer
        for (let i = 0; i < cur.roots.length; i++) if (c.signers.has(cur.roots[i])) yes++
        if (2 * yes > cur.roots.length) return accept({ dead: true })
      }
      pending = { id: candidates[0].id, epoch: candidates[0].body.epoch, roots: candidates[0].body.roots }
    }
    break
  }
  const m = pending ?? cur
  const authority = []
  for (let i = 0; i < m.roots.length; i++) if (!pending || has(cur.roots, m.roots[i])) authority[authority.length] = m.roots[i]
  const frozenBy = (x) => r.freezes.some((f) => f.membership === x.id && has(x.roots, f.signer))
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
  })
}

export function membershipState (records, context) {
  const ctx = readContext(context)
  if (ctx === undefined) throw new TypeError('context must hold identity, rpId, origin and witnessKeys')
  let r
  try {
    r = read(typeof records === 'object' && records !== null ? records : {}, ctx)
  } catch {
    return refuse('records')
  }
  for (const id of r.rootKeys.keys()) if (identityOf(id) === ctx.identity) return evaluate(id, ctx, r)
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
  for (let i = 0; i < revoked.length; i++) {
    const x = revoked[i]
    if (!isId(x)) return undefined
    let j = list.length
    while (list[j - 1] > x) j-- // list[-1] is undefined, which is never greater
    if (list[j - 1] !== x) apply(splice, list, [j, 0, x])
    if (list.length > MAX_REVOKED) return undefined
  }
  const memberships = state.pending ? [state.settled, state.membership] : [state.settled]
  // The settled epoch: a pending successor's is one more (R1).
  return freeze({ identity: state.identity, epoch: state.pending ? state.epoch - 1 : state.epoch,
    memberships: freeze(memberships), authority: state.authority, revoked: freeze(list), at })
}
