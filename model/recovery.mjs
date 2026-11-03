// Executable model of the membership rules R1–R5 (SPEC §5), and a bounded explorer.
//
// The model is independent of src/: roots are single letters, record ids are readable strings, and signatures are
// (payload, signer) pairs. It states what the rules decide, not how an implementation computes it.
//
// Items:
//   { kind: 'M', n, roots, prev, signer }  one root's signature over a membership payload (roots sorted)
//   { kind: 'F', n, signer }               one root's freeze of epoch n
//   { kind: 'W', id }                      a witness anchor on membership record `id` (variant `anchored` only)
//
// Variant `anchored`: a membership record counts only once a witness has anchored it, and the witness anchors only
// the first valid record it sees for each epoch. Two anchored records for one epoch still end the identity (R3).

export const MAX_ROOTS = 5

export const membershipId = (n, roots, prev) => `M${n}{${roots.join(',')}}<${prev}`
export const genesisOf = (root) => ({ id: membershipId(1, [root], '-'), n: 1, roots: [root] })

// R1: strict majority of the previous epoch's roots, and every added root, signed the payload.
function validNext (prev, p) {
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
export function evaluate (genesis, items, anchored = false) {
  const payloads = payloadsOf(items)
  const anchors = new Set(items.filter((it) => it.kind === 'W').map((it) => it.id))
  let cur = genesisOf(genesis)
  for (;;) {
    const next = []
    for (const p of payloads.values()) {
      if (p.n === cur.n + 1 && p.prev === cur.id && validNext(cur, p) && (!anchored || anchors.has(p.id))) next.push(p)
    }
    if (next.length > 1) return { dead: true, at: cur.n }
    if (next.length === 0) break
    cur = next[0]
  }
  let frozen = false
  for (const it of items) if (it.kind === 'F' && it.n === cur.n && cur.roots.includes(it.signer)) frozen = true
  return { dead: false, epoch: cur.n, roots: cur.roots, frozen, id: cur.id }
}

export const active = (s) => !s.dead && !s.frozen

// The witness: while the current epoch has a valid unanchored successor, anchor the first one (by id).
export function witness (genesis, items) {
  let out = items
  for (;;) {
    const e = evaluate(genesis, out, true)
    if (e.dead) return out
    const cur = { id: e.id, n: e.epoch, roots: e.roots }
    const next = [...payloadsOf(out).values()]
      .filter((p) => p.n === cur.n + 1 && p.prev === cur.id && validNext(cur, p)).map((p) => p.id).sort()
    if (next.length === 0) return out
    out = [...out, { kind: 'W', id: next[0] }]
  }
}

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

const itemKey = (it) => (it.kind === 'M' ? `${membershipId(it.n, it.roots, it.prev)}/${it.signer}` : it.kind === 'F' ? `F${it.n}/${it.signer}` : `W${it.id}`)
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
export function reach (genesis, start, holds, universe, maxEpoch, depth, anchored = false) {
  const seen = new Map([[setKey(start), start]])
  let frontier = [start]
  for (let d = 0; d < depth; d++) {
    const next = []
    for (const items of frontier) {
      for (const add of moves(genesis, items, holds, universe, maxEpoch)) {
        const s = anchored ? witness(genesis, [...items, ...add]) : [...items, ...add]
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
export function analyse ({ genesis, history: start, owner, thief, universe, maxEpoch, thiefDepth, anchored = false }) {
  const evaluate_ = (g, s) => evaluate(g, s, anchored)
  const reach_ = (g, s, holds, u, m, d) => reach(g, s, holds, u, m, d, anchored)
  const history = anchored ? witness(genesis, start) : start
  const thiefStates = reach_(genesis, history, thief, universe, maxEpoch, thiefDepth)

  const result = { thiefStates: thiefStates.length }

  // Can the thief, acting alone, control the current epoch, or end the identity?
  // Takeover: the current epoch is active and the owner holds none of its roots.
  result.takeover = thiefStates.find((s) => { const e = evaluate_(genesis, s); return active(e) && !e.roots.some((r) => owner.has(r)) }) ?? null
  result.kill = thiefStates.find((s) => evaluate_(genesis, s).dead) ?? null

  // After any thief play, can the owner in one move reach an active epoch with none of the thief's roots, which no
  // single further thief move undoes?
  const secure = (s) => { const e = evaluate_(genesis, s); return active(e) && !e.roots.some((r) => thief.has(r)) }
  result.unrecoverable = null
  for (const s of thiefStates) {
    const ok = reach_(genesis, s, owner, universe, maxEpoch, 1).some((q) =>
      secure(q) && reach_(genesis, q, thief, universe, maxEpoch, 1).every(secure))
    if (!ok) { result.unrecoverable = s; break }
  }

  // After any thief play, can the owner in one move leave the thief with no authority: the identity ended, or the
  // current epoch frozen in a way no single further thief move undoes?
  const noThiefAuthority = (s) => { const e = evaluate_(genesis, s); return !active(e) || !e.roots.some((r) => thief.has(r)) }
  result.cannotStop = null
  for (const s of thiefStates) {
    const ok = reach_(genesis, s, owner, universe, maxEpoch, 1).some((q) =>
      noThiefAuthority(q) && reach_(genesis, q, thief, universe, maxEpoch, 1).every(noThiefAuthority))
    if (!ok) { result.cannotStop = s; break }
  }

  // F-monotonicity of freezes: adding a freeze never turns an inactive state active.
  result.freezeRevives = null
  for (const s of thiefStates) {
    if (active(evaluate_(genesis, s))) continue
    for (const n of [1, 2, 3, 4]) {
      for (const signer of universe) {
        if (active(evaluate_(genesis, [...s, { kind: 'F', n, signer }]))) { result.freezeRevives = s; break }
      }
    }
  }
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
