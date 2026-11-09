// Executable model of the membership rules R1–R5 (SPEC §5), and a bounded explorer.
//
// The model is independent of src/: roots are single letters, record ids are readable strings, and signatures are
// (payload, signer) pairs. It states what the rules decide, not how an implementation computes it.
//
// Items:
//   { kind: 'M', n, roots, prev, signer }  one root's signature over a membership payload (roots sorted)
//   { kind: 'F', n, signer }               one root's freeze of epoch n
//   { kind: 'W', id, at }                  a witness anchor on membership record `id` at time `at` (anchored rules)
//   { kind: 'T', k }                       the k-th tick of the witness clock; the time is the number of ticks
//
// Rules for choosing between valid records for the same epoch:
//   'none'    as drafted: two valid records end the identity (R3).
//   'first'   a record counts only once anchored; the witness anchors only the first valid record per epoch.
//   'window'  the witness anchors every valid record extending the current chain, with its time. The earliest
//             anchored record wins, unless another was anchored less than WINDOW after it: then the identity ends.
//             Records anchored later than that are ignored.

export const MAX_ROOTS = 5
export const WINDOW = 1

export const membershipId = (n, roots, prev) => `M${n}{${roots.join(',')}}<${prev}`
export const genesisOf = (root) => ({ id: membershipId(1, [root], '-'), n: 1, roots: [root] })

// R1: the next epoch, signed by a strict majority of the previous epoch's roots and every root it adds.
export function validNext (prev, p) {
  if (p.n !== prev.n + 1) return false
  if (p.roots.length < 1 || p.roots.length > MAX_ROOTS) return false
  let yes = 0
  for (const r of prev.roots) if (p.signers.has(r)) yes++
  if (2 * yes <= prev.roots.length) return false
  for (const r of p.roots) if (!prev.roots.includes(r) && !p.signers.has(r)) return false
  return true
}

export function payloadsOf (items) {
  const payloads = new Map()
  for (const it of items) {
    if (it.kind !== 'M') continue
    const id = membershipId(it.n, it.roots, it.prev)
    let p = payloads.get(id)
    if (!p) payloads.set(id, (p = { id, n: it.n, roots: it.roots, prev: it.prev, signers: new Set() }))
    p.signers.add(it.signer)
  }
  return payloads
}

// R3–R5: the state is a function of the set of items. Returns
//   { dead: true, at }                         an equivocation froze epoch `at` permanently (R3)
//   { dead: false, epoch, roots, frozen, id }  the current epoch (R4) and whether a freeze applies (R2)
export function evaluate (genesis, items, rule = 'none') {
  const payloads = payloadsOf(items)
  const anchoredAt = new Map()
  for (const it of items) {
    if (it.kind === 'W' && !(anchoredAt.get(it.id) <= it.at)) anchoredAt.set(it.id, it.at)
  }
  let cur = genesisOf(genesis)
  const chain = [cur]
  for (;;) {
    const next = []
    for (const p of payloads.values()) {
      if (p.n === cur.n + 1 && p.prev === cur.id && validNext(cur, p) && (rule === 'none' || anchoredAt.has(p.id))) next.push(p)
    }
    if (next.length === 0) break
    if (rule === 'window') {
      next.sort((x, y) => anchoredAt.get(x.id) - anchoredAt.get(y.id) || (x.id < y.id ? -1 : 1))
      const t = anchoredAt.get(next[0].id)
      if (next.some((p, i) => i > 0 && anchoredAt.get(p.id) < t + WINDOW)) return { dead: true, at: cur.n }
    } else if (next.length > 1) {
      return { dead: true, at: cur.n }
    }
    cur = next[0]
    chain.push(cur)
  }
  let frozen = false
  for (const it of items) if (it.kind === 'F' && it.n === cur.n && cur.roots.includes(it.signer)) frozen = true
  return { dead: false, epoch: cur.n, roots: cur.roots, frozen, id: cur.id, chain }
}

export const active = (s) => !s.dead && !s.frozen

// The witness, run after every move. 'first': anchor the first valid successor of the current epoch, by id.
// 'window': anchor, at the current time, every valid record whose previous epoch is on the current chain.
export function witness (genesis, items, rule) {
  if (rule === 'none') return items
  const now = items.filter((it) => it.kind === 'T').length
  let out = items
  for (;;) {
    const e = evaluate(genesis, out, rule)
    if (e.dead) return out
    const anchored = new Set(out.filter((it) => it.kind === 'W').map((it) => it.id))
    const onChain = rule === 'window' ? e.chain : [e.chain[e.chain.length - 1]]
    const fresh = [...payloadsOf(out).values()]
      .filter((p) => !anchored.has(p.id) && onChain.some((c) => p.n === c.n + 1 && p.prev === c.id && validNext(c, p)))
      .map((p) => p.id).sort()
    if (fresh.length === 0) return out
    const add = rule === 'window' ? fresh : fresh.slice(0, 1)
    out = [...out, ...add.map((id) => ({ kind: 'W', id, at: now }))]
  }
}

export const tick = (items) => [...items, { kind: 'T', k: items.filter((it) => it.kind === 'T').length }]

// Every nonempty subset of `universe` with at most MAX_ROOTS members, sorted.
export function subsets (universe) {
  const out = []
  const u = [...universe].sort()
  for (let mask = 1; mask < 1 << u.length; mask++) {
    const s = u.filter((_, i) => mask & (1 << i))
    if (s.length <= MAX_ROOTS) out.push(s)
  }
  return out
}

const itemKey = (it) => it.kind === 'M' ? `${membershipId(it.n, it.roots, it.prev)}/${it.signer}`
  : it.kind === 'F' ? `F${it.n}/${it.signer}` : it.kind === 'W' ? `W${it.id}@${it.at}` : `T${it.k}`
export const setKey = (items) => items.map(itemKey).sort().join(' ')

// One move: an actor publishes a payload signed by every root it holds that could matter, or freezes an epoch with
// every root it holds. Signing with fewer roots never makes a record valid that more roots would not, and a
// signature the actor withholds can be published by a later move.
export function moves (genesis, items, holds, universe, maxEpoch) {
  const known = [genesisOf(genesis), ...payloadsOf(items).values()]
  const have = new Set(items.map(itemKey))
  const out = []
  for (const q of known) {
    if (q.n + 1 > maxEpoch) continue
    for (const roots of subsets(universe)) {
      const signers = [...holds].filter((r) => q.roots.includes(r) || roots.includes(r)).sort()
      const add = signers.map((signer) => ({ kind: 'M', n: q.n + 1, roots, prev: q.id, signer }))
        .filter((it) => !have.has(itemKey(it)))
      if (add.length) out.push(add)
    }
  }
  const epochs = new Set(known.map((q) => q.n))
  for (const n of epochs) {
    const add = [...holds].sort().map((signer) => ({ kind: 'F', n, signer })).filter((it) => !have.has(itemKey(it)))
    if (add.length) out.push(add)
  }
  return out
}

// Every item set reachable from `start` by at most `depth` moves of one actor (deduplicated), including `start`.
export function reach (genesis, start, holds, universe, maxEpoch, depth, rule = 'none') {
  const seen = new Map([[setKey(start), start]])
  let frontier = [start]
  for (let d = 0; d < depth; d++) {
    const next = []
    for (const items of frontier) {
      for (const add of moves(genesis, items, holds, universe, maxEpoch)) {
        const s = witness(genesis, [...items, ...add], rule)
        const k = setKey(s)
        if (!seen.has(k)) { seen.set(k, s); next.push(s) }
      }
    }
    frontier = next
  }
  return [...seen.values()]
}

// The questions asked of each scenario. `owner` holds every root of the scenario (theft copies a passkey, it does
// not remove it) plus a fresh root `o`; `thief` holds the stolen roots plus a fresh root `t`.
// Under 'window', the honest history is anchored and then left for longer than WINDOW before the theft; the thief
// plays within one window, and the owner answers within the same window (the witness notifies the owner). Whether
// the owner's position survives is checked against a further thief move both now and after the window closes.
export function analyse ({ genesis, history: start, owner, thief, universe, maxEpoch, thiefDepth, rule = 'none' }) {
  const ev = (s) => evaluate(genesis, s, rule)
  const by = (holds, s, depth) => reach(genesis, s, holds, universe, maxEpoch, depth, rule)
  // A further thief move, now or (under 'window') after the window has closed.
  const thiefNext = (s) => (rule === 'window' ? [...by(thief, s, 1), ...by(thief, tick(s), 1)] : by(thief, s, 1))

  let history = witness(genesis, start, rule)
  if (rule === 'window') for (let i = 0; i <= WINDOW; i++) history = tick(history)
  const thiefStates = by(thief, history, thiefDepth)
  const result = { thiefStates: thiefStates.length }

  // Takeover: the current epoch is active and the owner holds none of its roots. Kill: the identity has ended.
  result.takeover = thiefStates.find((s) => { const e = ev(s); return active(e) && !e.roots.some((r) => owner.has(r)) }) ?? null
  result.kill = thiefStates.find((s) => ev(s).dead) ?? null

  // After any thief play, can the owner in one move reach an active epoch with none of the thief's roots, which no
  // further thief move undoes?
  const secure = (s) => { const e = ev(s); return active(e) && !e.roots.some((r) => thief.has(r)) }
  result.unrecoverable = thiefStates.find((s) => !by(owner, s, 1).some((q) => secure(q) && thiefNext(q).every(secure))) ?? null

  // After any thief play, can the owner in one move leave the thief with no authority, in a way no further thief
  // move undoes?
  const noThiefAuthority = (s) => { const e = ev(s); return !active(e) || !e.roots.some((r) => thief.has(r)) }
  result.cannotStop = thiefStates.find((s) =>
    !by(owner, s, 1).some((q) => noThiefAuthority(q) && thiefNext(q).every(noThiefAuthority))) ?? null

  // Under 'window': if the owner does not answer before the window closes, is a thief takeover then final?
  if (rule === 'window') {
    result.lateOwnerCannotStop = thiefStates.find((s) => { const e = ev(s); return active(e) && !e.roots.some((r) => owner.has(r)) &&
      !by(owner, tick(s), 1).some((q) => noThiefAuthority(q)) }) ?? null
  }

  // A freeze never turns an inactive state active.
  result.freezeRevives = thiefStates.find((s) => !active(ev(s)) &&
    [1, 2, 3, 4].some((n) => universe.some((signer) => active(ev([...s, { kind: 'F', n, signer }]))))) ?? null
  return result
}

// Honest history: each epoch's payload signed by every root of the previous epoch and every root it adds.
export function history (genesis, epochs) {
  const items = []
  let prev = genesisOf(genesis)
  for (const roots of epochs) {
    const sorted = [...roots].sort()
    const p = { n: prev.n + 1, roots: sorted, prev: prev.id }
    for (const signer of new Set([...prev.roots, ...sorted])) items.push({ kind: 'M', ...p, signer })
    prev = { id: membershipId(p.n, sorted, p.prev), n: p.n, roots: sorted }
  }
  return items
}
