// Executable model of membership with witness settlement (SPEC §5, R1–R7), and a bounded explorer.
//
// Items (roots are letters; ids are readable strings; a signature is a (payload, signer) pair):
//   { kind: 'M', n, roots, prev, signer }   a root's signature on a membership record; epoch 2's prev is the identity
//   { kind: 'C', record, signer }           a root's signature on a contest of membership record `record`
//   { kind: 'F', target, signer }           a root's freeze of membership record `target`
//   { kind: 'A', id, at }                   the witness's anchor on a membership or contest record
//   { kind: 'S', prev, outcome, at }        the witness's settlement of the successor of `prev`: a record id or 'contested'
//   { kind: 'T', k }                        the k-th tick of the witness clock
// Recovery (R11). An 'M' item may carry `rec` (the membership's designation of recovery parties) and may be signed
// by a recovery party of its predecessor; such a record with enough of them is a recovery. The witness does not
// anchor one as it does an ordinary record. It puts it under notice, and anchors it only once it has matured:
//   { kind: 'N', id, at }                   the witness's notice of recovery `id`: its window began at `at`
//   { kind: 'X', record, signer }           a root's cancel of recovery `record`
//   { kind: 'K', id, at }                   the witness's statement that recovery `id` was cancelled
//   { kind: 'U', id, at }                   the witness's statement that recovery `id` matured: nothing cancelled it
//
// The witness is honest here; its own failures are residuals in the spec. Verifiers may hold any subset of the items.

import { membershipId, genesisOf, payloadsOf, validNext, recoveryOf, subsets, rule, COOL } from './recovery.mjs'

export const WINDOW = 1
export const contestId = (record) => `C<${record}`
const now = (items) => items.filter((it) => it.kind === 'T').length

function contestsOf (items) {
  const out = new Map()
  for (const it of items) {
    if (it.kind !== 'C') continue
    const id = contestId(it.record)
    if (!out.has(id)) out.set(id, { id, record: it.record, signers: new Set() })
    out.get(id).signers.add(it.signer)
  }
  return out
}

// R5: a contest is valid if a strict majority of the contested record's predecessor signed it.
const validContest = (base, c) => 2 * base.roots.filter((r) => c.signers.has(r)).length > base.roots.length

// What a verifier holding `items` decides. Returns
//   { dead: true }                                       contested, or the witness contradicted itself
//   { dead: false, record, base, pending, authority, frozen, chain, notice }
// `record` is the effective membership; while it is pending, `authority` is only the roots it shares with `base`.
// `notice` is the recovery of `base` under notice, { id, at }, or null: one the witness gave notice of and has not
// said was cancelled, and that is not yet anchored. It changes nobody's authority.
export function evaluate (genesis, items) {
  const payloads = payloadsOf(items)
  const contests = contestsOf(items)
  const matured = new Set(items.filter((it) => it.kind === 'U').map((it) => it.id))
  const anchors = new Map()
  for (const it of items) if (it.kind === 'A' && !(anchors.get(it.id) <= it.at)) anchors.set(it.id, it.at)
  let cur = genesisOf(genesis)
  const chain = [cur]
  let pending = null
  for (;;) {
    const settled = new Set(items.filter((it) => it.kind === 'S' && it.prev === cur.id).map((it) => it.outcome))
    if (settled.size > 1 || settled.has('contested')) return { dead: true }
    if (settled.size === 1) {
      const next = payloads.get([...settled][0])
      if (!next || next.prev !== cur.id || !validNext(cur, next, matured.has(next.id))) break // stale: the settled record is not held
      cur = next
      chain.push(cur)
      continue
    }
    const anchored = [...payloads.values()].filter((p) => p.prev === cur.id && anchors.has(p.id) && validNext(cur, p, matured.has(p.id)))
    const contest = anchored.length === 1 ? contests.get(contestId(anchored[0].id)) : undefined
    if (anchored.length > 1) return { dead: true }
    if (anchored.length === 1 && contest && anchors.has(contest.id) && validContest(cur, contest)) return { dead: true }
    if (anchored.length === 1) pending = anchored[0]
    break
  }
  const record = pending ?? cur
  const authority = pending ? record.roots.filter((r) => cur.roots.includes(r)) : record.roots
  // R2: a freeze on the last settled membership still applies while its successor is pending.
  const frozenBy = (m) => items.some((it) => it.kind === 'F' && it.target === m.id && m.roots.includes(it.signer))
  const frozen = frozenBy(record) || (!!pending && frozenBy(cur))
  const cancelled = new Set(items.filter((it) => it.kind === 'K').map((it) => it.id))
  const noticed = items.filter((it) => it.kind === 'N' && payloads.get(it.id)?.prev === cur.id && !cancelled.has(it.id) && !anchors.has(it.id))
    .sort((a, b) => b.at - a.at || (a.id < b.id ? -1 : 1))
  const notice = noticed.length > 0 ? { id: noticed[0].id, at: noticed[0].at } : null
  return { dead: false, record, base: cur, pending: !!pending, authority, frozen, chain: chain.map((c) => c.id), notice }
}

export const active = (e) => !e.dead && !e.frozen

// The witness, run after every move with the full item set. It anchors only the first valid successor of the last
// settled record; while that successor is inside its window it anchors a valid contest; once the window has passed
// it settles. An ordinary rival, or anything arriving after settlement, is never anchored (R3). Of several valid
// successors (held while their predecessor was pending), `pick` chooses the one anchored: by default the first id.
// It chooses likewise among recoveries that could be put under notice.
export function witness (genesis, items, pick = (ids) => ids[0]) {
  let out = items
  for (;;) {
    const t = now(out)
    // The witness's own view ignores contest anchors, so that a contested epoch can still be settled as contested.
    const e = evaluate(genesis, out.filter((it) => !(it.kind === 'A' && it.id.startsWith('C'))))
    if (e.dead) return out
    const cur = payloadsOf(out).get(e.base.id) ?? genesisOf(genesis)
    const anchoredIds = new Set(out.filter((it) => it.kind === 'A').map((it) => it.id))
    if (!e.pending) {
      const has = (kind, id) => out.some((it) => it.kind === kind && it.id === id)
      const successors = [...payloadsOf(out).values()].filter((p) => p.prev === cur.id)
      const next = successors.filter((p) => validNext(cur, p, has('U', p.id))).map((p) => p.id).sort()
      if (next.length > 0) {
        out = [...out, { kind: 'A', id: pick(next), at: t }]
        continue
      }
      // R11. No ordinary successor: a recovery of the settled membership. One is under notice at a time. A cancel by
      // any root of that membership ends it, and the membership is as it was; left alone for its window, it matures,
      // and is anchored above like any record, its contest window still to come.
      const recoveries = successors.filter((p) => recoveryOf(cur, p))
      const under = recoveries.find((p) => has('N', p.id) && !has('K', p.id) && !has('U', p.id))
      if (under) {
        const began = Math.min(...out.filter((it) => it.kind === 'N' && it.id === under.id).map((it) => it.at))
        if (rule('cancel') && out.some((it) => it.kind === 'X' && it.record === under.id && cur.roots.includes(it.signer))) {
          out = [...out, { kind: 'K', id: under.id, at: t }]
          continue
        }
        if (!rule('mature') || t >= began + cur.rec.w) {
          out = [...out, { kind: 'U', id: under.id, at: t }]
          continue
        }
        return out
      }
      const last = Math.max(-Infinity, ...out.filter((it) => it.kind === 'K').map((it) => it.at))
      const fresh = recoveries.filter((p) => !has('N', p.id)).map((p) => p.id).sort()
      if (fresh.length === 0 || (rule('cool') && t < last + COOL)) return out
      out = [...out, { kind: 'N', id: pick(fresh), at: t }]
      continue
    }
    const at = Math.min(...out.filter((it) => it.kind === 'A' && it.id === e.record.id).map((it) => it.at))
    const contest = contestsOf(out).get(contestId(e.record.id))
    if (t < at + WINDOW) {
      if (contest && !anchoredIds.has(contest.id) && validContest(cur, contest)) {
        out = [...out, { kind: 'A', id: contest.id, at: t }]
        continue
      }
      return out
    }
    const contested = contest && anchoredIds.has(contest.id)
    if (out.some((it) => it.kind === 'S' && it.prev === cur.id)) return out
    out = [...out, { kind: 'S', prev: cur.id, outcome: contested ? 'contested' : e.record.id, at: t }]
    if (contested) return out
  }
}

export const tick = (genesis, items) => witness(genesis, [...items, { kind: 'T', k: now(items) }])

const itemKey = (it) => {
  switch (it.kind) {
    case 'M': return `${membershipId(it.n, it.roots, it.prev, it.rec ?? null)}/${it.signer}`
    case 'C': return `${contestId(it.record)}/${it.signer}`
    case 'F': return `F${it.target}/${it.signer}`
    case 'A': return `A${it.id}@${it.at}`
    case 'S': return `S${it.prev}=${it.outcome}@${it.at}`
    case 'N': case 'K': case 'U': return `${it.kind}${it.id}@${it.at}`
    case 'X': return `X${it.record}/${it.signer}`
    default: return `T${it.k}`
  }
}
export const setKey = (items) => items.map(itemKey).sort().join(' ')

// One move by an actor holding `holds`: sign a membership record, a contest or a freeze with every root it holds
// that could matter. Ticks are separate (see `reach`).
// `designations` lists the `rec` values an ordinary record may carry besides its predecessor's own (none by default,
// so explorations without recovery are as they were). A holder of a recovery party's key signs recoveries of every
// known membership that designates it; a holder of a root of a membership cancels every recovery of it.
export function moves (genesis, items, holds, universe, maxEpoch, designations = []) {
  const known = [genesisOf(genesis), ...payloadsOf(items).values()]
  const have = new Set(items.map(itemKey))
  const out = []
  const fresh = (add) => { const a = add.filter((it) => !have.has(itemKey(it))); if (a.length) out.push(a) }
  for (const q of known) {
    const mine = [...holds].filter((r) => q.roots.includes(r)).sort()
    if (q.n + 1 <= maxEpoch) {
      for (const roots of subsets(universe)) {
        const parties = q.rec ? q.rec.parties : []
        const signers = [...holds].filter((r) => q.roots.includes(r) || roots.includes(r) || parties.includes(r)).sort()
        for (const rec of new Set([q.rec, ...designations])) {
          if (rec && rec.parties.some((g) => roots.includes(g))) continue
          fresh(signers.map((signer) => (rec ? { kind: 'M', n: q.n + 1, roots, prev: q.id, rec, signer } : { kind: 'M', n: q.n + 1, roots, prev: q.id, signer })))
        }
      }
    }
    fresh(mine.map((signer) => ({ kind: 'F', target: q.id, signer })))
    // A contest of q is signed by the roots of q's predecessor.
    const base = known.find((x) => x.id === q.prev)
    if (base) fresh([...holds].filter((r) => base.roots.includes(r)).sort().map((signer) => ({ kind: 'C', record: q.id, signer })))
    if (base && recoveryOf(base, q)) fresh([...holds].filter((r) => base.roots.includes(r)).sort().map((signer) => ({ kind: 'X', record: q.id, signer })))
  }
  return out
}

// Item sets reachable by at most `depth` moves of one actor, each followed by the witness; with `ticks`, a tick also
// counts as a move.
export function reach (genesis, start, holds, universe, maxEpoch, depth, ticks = false, designations = []) {
  const seen = new Map([[setKey(start), start]])
  let frontier = [start]
  for (let d = 0; d < depth; d++) {
    const next = []
    for (const items of frontier) {
      const succ = moves(genesis, items, holds, universe, maxEpoch, designations).map((add) => witness(genesis, [...items, ...add]))
      if (ticks) succ.push(tick(genesis, items))
      for (const s of succ) {
        const k = setKey(s)
        if (!seen.has(k)) { seen.set(k, s); next.push(s) }
      }
    }
    frontier = next
  }
  return [...seen.values()]
}

// Honest history: each epoch signed by its predecessor's roots and every root it adds, anchored and settled.
export function history (genesis, epochs) {
  let items = []
  let prev = genesisOf(genesis)
  for (const epoch of epochs) {
    // An epoch is its roots, or { roots, rec } to designate recovery parties with it.
    const sorted = [...(epoch.roots ?? epoch)].sort()
    const rec = epoch.rec ?? null
    for (const signer of new Set([...prev.roots, ...sorted])) items.push(rec ? { kind: 'M', n: prev.n + 1, roots: sorted, prev: prev.id, rec, signer } : { kind: 'M', n: prev.n + 1, roots: sorted, prev: prev.id, signer })
    items = witness(genesis, items)
    for (let i = 0; i <= WINDOW; i++) items = tick(genesis, items)
    prev = { id: membershipId(prev.n + 1, sorted, prev.id, rec), n: prev.n + 1, roots: sorted, rec }
  }
  for (let i = 0; i <= WINDOW; i++) items = tick(genesis, items)
  return items
}

// Views: every subset of the items, taking a record's signatures together. A network attacker chooses the view.
function groups (items) {
  const by = new Map()
  for (const it of items) {
    if (it.kind === 'T') continue
    const k = it.kind === 'M' ? membershipId(it.n, it.roots, it.prev, it.rec ?? null) : it.kind === 'C' ? contestId(it.record) : it.kind === 'X' ? `X${it.record}` : itemKey(it)
    if (!by.has(k)) by.set(k, [])
    by.get(k).push(it)
  }
  return [...by.values()]
}

// A view's effective record must lie on the chain the full item set gives (settled records and the pending one): a
// view may be stale, never forked. If the full set is dead, any anchored record is allowed (every view is then stale).
// Returns a counterexample view, or null.
export function forkedView (genesis, items) {
  const full = evaluate(genesis, items)
  const allowed = new Set(full.dead
    ? items.filter((it) => it.kind === 'A').map((it) => it.id)
    : [...full.chain, full.record.id])
  allowed.add(genesisOf(genesis).id)
  const g = groups(items)
  if (g.length > 14) throw new Error(`too many groups for exhaustive views: ${g.length}`)
  for (let mask = 0; mask < 1 << g.length; mask++) {
    const view = g.filter((_, i) => mask & (1 << i)).flat()
    const e = evaluate(genesis, view)
    if (!e.dead && !allowed.has(e.record.id)) return view
  }
  return null
}

// The questions asked of each scenario (see recovery.mjs for the conventions on `owner` and `thief`).
export function analyse ({ genesis, history: start, owner, thief, universe, maxEpoch, thiefDepth }) {
  const ev = (s) => evaluate(genesis, s)
  const by = (holds, s, depth, ticks = false) => reach(genesis, s, holds, universe, maxEpoch, depth, ticks)
  const thiefOnly = (r) => thief.has(r) && !owner.has(r)
  // The thief's further play: a move now, a move after the window, or just waiting.
  const thiefNext = (s) => [...by(thief, s, 1), ...by(thief, tick(genesis, s), 1), tick(genesis, tick(genesis, s))]

  const thiefStates = by(thief, start, thiefDepth)
  const result = { thiefStates: thiefStates.length }

  result.takeover = thiefStates.map((s) => tick(genesis, tick(genesis, s))).find((s) => {
    const e = ev(s); return active(e) && !e.authority.some((r) => owner.has(r))
  }) ?? null
  result.pendingThiefAuthority = by(thief, start, thiefDepth, true).find((s) => {
    const e = ev(s); return active(e) && e.pending && e.authority.some(thiefOnly)
  }) ?? null
  result.kill = by(thief, start, thiefDepth, true).find((s) => ev(s).dead) ?? null

  // Secure: the thief has no authority now, and once the window has passed the owner's membership is active and
  // free of the thief's roots. (A thief's freeze of the old membership may hold the owner up until settlement.)
  const settle = (s) => tick(genesis, tick(genesis, s))
  const secure = (s) => {
    const now = ev(s)
    if (active(now) && now.authority.some((r) => thief.has(r))) return false
    const later = ev(settle(s))
    return active(later) && !later.authority.some((r) => thief.has(r))
  }
  result.unrecoverable = thiefStates.find((s) => !by(owner, s, 1).some((q) => secure(q) && thiefNext(q).every(secure))) ?? null

  const noThiefAuthority = (s) => { const e = ev(s); return !active(e) || !e.authority.some((r) => thief.has(r)) }
  result.cannotStop = thiefStates.find((s) =>
    !by(owner, s, 1).some((q) => noThiefAuthority(q) && thiefNext(q).every(noThiefAuthority))) ?? null

  result.lateOwnerCannotStop = thiefStates.find((s) => {
    const late = tick(genesis, tick(genesis, s))
    const e = ev(late)
    return active(e) && !e.authority.some((r) => owner.has(r)) && !by(owner, late, 1).some(noThiefAuthority)
  }) ?? null

  result.forked = null
  for (const s of [...thiefStates, ...thiefStates.map((x) => tick(genesis, tick(genesis, x)))]) {
    const v = forkedView(genesis, s)
    if (v) { result.forked = { state: s, view: v }; break }
  }
  return result
}
