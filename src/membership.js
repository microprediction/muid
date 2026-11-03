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
const { includes } = Array.prototype

const ID = /^[0-9a-f]{64}$/
const MAX_ROOTS = 5
const isId = (x) => typeof x === 'string' && apply(exec, ID, [x]) !== null
const isTime = (x) => isSafeInteger(x) && x >= 0
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

// A root-signed record of `type` whose body passes `bodyOk`: { id, body, signer }, or undefined.
function rootSigned (text, type, bodyOk, ctx, rootKeys) {
  const r = opened(text, type)
  if (r === undefined || !bodyOk(r.body) || !onlyKeys(r.sig, ['assertion', 'root'])) return undefined
  const key = rootKeys.get(r.sig.root)
  if (key === undefined) return undefined
  const a = checkRootAssertion(r.sig.assertion, { record: r.id, rpId: ctx.rpId, origin: ctx.origin, key })
  return a.ok ? { id: r.id, body: r.body, signer: r.sig.root } : undefined
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
  for (let i = 0; i < cur.roots.length; i++) if (p.signers.has(cur.roots[i])) yes++
  if (2 * yes <= cur.roots.length) return false
  for (let i = 0; i < p.body.roots.length; i++) {
    const r = p.body.roots[i]
    if (!has(cur.roots, r) && !p.signers.has(r)) return false
  }
  return true
}

function list (records, key) {
  const x = records[key]
  return isArray(x) ? x : []
}

// Index loops only: decoded arrays have no prototype, and a caller's array could have a replaced iterator.
function copy (a) {
  const out = []
  for (let i = 0; i < a.length; i++) out[i] = a[i]
  return out
}

function read (records, ctx) {
  const rootKeys = new Map()
  const rootsTexts = copy(list(records, 'roots'))
  for (let i = 0; i < rootsTexts.length; i++) {
    const t = rootsTexts[i]
    const r = checkRoot(t, { rpId: ctx.rpId })
    if (r.ok) rootKeys.set(r.id, r.key)
  }
  const mine = (b) => b.identity === ctx.identity
  const memberships = new Map()
  const membershipsTexts = copy(list(records, 'memberships'))
  for (let i = 0; i < membershipsTexts.length; i++) {
    const t = membershipsTexts[i]
    const m = rootSigned(t, 'membership', (b) => onlyKeys(b, ['epoch', 'identity', 'prev', 'roots']) && mine(b) &&
      isTime(b.epoch) && isId(b.prev) && rootsOk(b.roots), ctx, rootKeys)
    if (m === undefined) continue
    if (!memberships.has(m.id)) memberships.set(m.id, { id: m.id, body: m.body, signers: new Set() })
    memberships.get(m.id).signers.add(m.signer)
  }
  const contests = new Map()
  const contestsTexts = copy(list(records, 'contests'))
  for (let i = 0; i < contestsTexts.length; i++) {
    const t = contestsTexts[i]
    const c = rootSigned(t, 'contest', (b) => onlyKeys(b, ['identity', 'record']) && mine(b) && isId(b.record), ctx, rootKeys)
    if (c === undefined) continue
    if (!contests.has(c.body.record)) contests.set(c.body.record, { id: c.id, signers: new Set() })
    contests.get(c.body.record).signers.add(c.signer)
  }
  const freezes = []
  const freezesTexts = copy(list(records, 'freezes'))
  for (let i = 0; i < freezesTexts.length; i++) {
    const t = freezesTexts[i]
    const f = rootSigned(t, 'freeze', (b) => onlyKeys(b, ['identity', 'membership']) && mine(b) && isId(b.membership), ctx, rootKeys)
    if (f !== undefined) freezes[freezes.length] = { membership: f.body.membership, signer: f.signer }
  }
  const anchored = new Set()
  const anchorsTexts = copy(list(records, 'anchors'))
  for (let i = 0; i < anchorsTexts.length; i++) {
    const t = anchorsTexts[i]
    const a = witnessSigned(t, 'anchor', (b) => onlyKeys(b, ['at', 'identity', 'record']) && mine(b) && isTime(b.at) &&
      isId(b.record), ctx)
    if (a !== undefined) anchored.add(a.record)
  }
  const settled = new Map()
  const settlementsTexts = copy(list(records, 'settlements'))
  for (let i = 0; i < settlementsTexts.length; i++) {
    const t = settlementsTexts[i]
    const s = witnessSigned(t, 'settlement', (b) => onlyKeys(b, ['at', 'identity', 'outcome', 'prev']) && mine(b) &&
      isTime(b.at) && isId(b.prev) && (b.outcome === 'contested' || isId(b.outcome)), ctx)
    if (s === undefined) continue
    if (!settled.has(s.prev)) settled.set(s.prev, new Set())
    settled.get(s.prev).add(s.outcome)
  }
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
    membership: m.id,
    epoch: m.epoch,
    roots: freeze(copy(m.roots)),
    pending: pending !== undefined,
    authority: freeze(authority),
    frozen: frozenBy(m) || (pending !== undefined && frozenBy(cur)),
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
