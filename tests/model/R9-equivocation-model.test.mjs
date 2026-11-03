// Decision 10 against the model: over every history the explorer reaches with an honest witness (an actor holding
// every root makes every move, and the clock ticks), no head is refused as equivocation after any head the witness
// signed earlier on the same history. Heads from histories that diverge (what a lying witness could show two relying
// parties) are refused in part. Every distinct honest pair, and a sample of diverging ones, is replayed through the
// real verifier.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { evaluate, moves, witness, tick, setKey } from '../../model/settled.mjs'
import { genesisOf } from '../../model/recovery.mjs'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const G = 'a'
const SCENARIOS = [[['a', 'b'], 3, 5], [['a', 'b', 'c'], 3, 4]]

// The head the honest witness signs for an item set (R9): none for a dead or frozen identity or one without authority.
function headOf (items) {
  const e = evaluate(G, items)
  if (e.dead || e.frozen || e.authority.length === 0) return null
  const memberships = e.pending ? [e.base.id, e.record.id] : [e.base.id]
  return { epoch: e.base.n, memberships, at: items.filter((it) => it.kind === 'T').length }
}
const key = (h) => JSON.stringify(h)

// SPEC F5 and decision 10, stated independently of src/verifier.js.
function equivocates (last, h) {
  const [settled, pending] = last.memberships
  if (h.epoch < last.epoch) return true
  if (h.epoch === last.epoch) return h.memberships[0] !== settled || (pending !== undefined && h.memberships[1] !== pending)
  return h.epoch === last.epoch + 1 && pending !== undefined && h.memberships[0] !== pending
}

// Every state reachable in `depth` steps, each with the heads signed before it on some history leading to it.
function explore (universe, maxEpoch, depth) {
  const holds = new Set(universe)
  const states = new Map([['', { items: [], depth: 0 }]])
  let frontier = ['']
  for (let d = 0; d < depth; d++) {
    const next = []
    for (const k of frontier) {
      const { items } = states.get(k)
      const succ = moves(G, items, holds, universe, maxEpoch).map((add) => witness(G, [...items, ...add]))
      succ.push(tick(G, items))
      for (const s of succ) {
        const sk = setKey(s)
        if (!states.has(sk)) { states.set(sk, { items: s, depth: d + 1, parents: new Set() }); next.push(sk) }
        states.get(sk).parents?.add(k)
      }
    }
    frontier = next
  }
  // Items only accumulate, so ordering by item count puts every parent before its children.
  const order = [...states.keys()].sort((x, y) => states.get(x).items.length - states.get(y).items.length)
  for (const k of order) {
    const s = states.get(k)
    s.head = headOf(s.items)
    s.before = new Map()
    for (const p of s.parents ?? []) {
      const ps = states.get(p)
      for (const [hk, h] of ps.before) s.before.set(hk, h)
      if (ps.head) s.before.set(key(ps.head), ps.head)
    }
  }
  return states
}

const results = SCENARIOS.map(([universe, maxEpoch, depth]) => ({ name: `${universe.join(', ')}; epochs to ${maxEpoch}; ${depth} steps`, states: explore(universe, maxEpoch, depth) }))

for (const { name, states } of results) {
  test(`${name}: no honest later head is refused after an earlier one`, () => {
    let pairs = 0
    const kinds = new Set()
    for (const s of states.values()) {
      if (!s.head) continue
      for (const last of s.before.values()) {
        pairs++
        assert.ok(last.at <= s.head.at, 'heads are signed in time order')
        assert.equal(equivocates(last, s.head), false, `${key(last)} then ${key(s.head)}`)
        kinds.add(`${s.head.epoch - last.epoch}${last.memberships.length}${s.head.memberships.length}`)
      }
    }
    assert.ok(pairs > 1000, `pairs checked: ${pairs}`)
    // Anti-vacuity: the honest pairs include each progression the rule distinguishes.
    for (const k of ['011', '012', '022', '121', '122', '111', '221']) assert.ok(kinds.has(k), `progression ${k} reached`)
  })

  test(`${name}: heads from diverging histories are refused in part`, () => {
    const heads = new Map()
    for (const s of states.values()) if (s.head) heads.set(key(s.head), s.head)
    const all = [...heads.values()]
    let flagged = 0
    for (const a of all) for (const b of all) if (a.at <= b.at && equivocates(a, b)) flagged++
    assert.ok(all.length > 20 && flagged > 20, `heads ${all.length}, flagged ${flagged}`)
  })
}

// Replay through the real verifier: model ids become hex ids (the genesis is the identity), heads are signed by a
// pinned witness key, and a delegation is made under the presented head's settled membership.
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_000
const W = Uint8Array.from({ length: 32 }, (_, i) => 3 + i)
const APP = Uint8Array.from({ length: 32 }, (_, i) => 90 + i)
const AUD = 'https://app.example'
const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD,
  witnessKeys: [{ key: hex(ed25519.getPublicKey(W)), nbf: 0, exp: NOW + 1000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const I = rootModule.identityOf(ROOT)
const idOf = (m) => (m === genesisOf(G).id ? I : createHash('sha256').update(m).digest('hex'))
const delegations = new Map()
function delegationFor (membership) {
  if (!delegations.has(membership)) {
    const { payload, id } = envelope.seal('delegation', { identity: I, membership, root: ROOT, subject: hex(ed25519.getPublicKey(APP)),
      aud: AUD, scopes: ['post'], nbf: NOW - 100, exp: NOW + 1000 })
    const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
    delegations.set(membership, envelope.wrap(payload, { root: make({ covers: [id] }), subject }))
  }
  return delegations.get(membership)
}
const signedHeads = new Map()
function signed (h) {
  if (signedHeads.has(key(h))) return signedHeads.get(key(h))
  const { payload } = envelope.seal('head', { identity: I, epoch: h.epoch, memberships: h.memberships.map(idOf), authority: [ROOT],
    revoked: [], at: NOW - 100 + h.at })
  signedHeads.set(key(h), envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), W)),
    witness: hex(ed25519.getPublicKey(W)) }))
  return signedHeads.get(key(h))
}

test('the real verifier accepts every distinct honest pair and refuses a sample of diverging ones', () => {
  const { states } = results[1]
  const distinct = new Map()
  for (const s of states.values()) if (s.head) for (const last of s.before.values()) distinct.set(key([last, s.head]), [last, s.head])
  const honest = [...distinct.values()]
  const heads = [...new Map([...states.values()].filter((s) => s.head).map((s) => [key(s.head), s.head])).values()]
  const diverging = []
  for (const a of heads) for (const b of heads) if (a.at <= b.at && equivocates(a, b)) diverging.push([a, b])
  // A fixed stride, so the sample covers the whole list and reproduces.
  const sample = (list, n) => list.filter((_, i) => i % Math.max(1, Math.floor(list.length / n)) === 0).slice(0, n)
  for (const [expectOk, pairs] of [[true, honest], [false, sample(diverging, 300)]]) {
    assert.ok(pairs.length >= 300, `pairs: ${pairs.length}`)
    for (const [last, h] of pairs) {
      const r = v.verifyDelegation({ delegation: delegationFor(idOf(h.memberships[0])), root: rootText, head: signed(h) },
        { now: NOW, scope: 'post', revoked: [], lastHead: signed(last) })
      if (expectOk) assert.equal(r.ok, true, `${key(last)} then ${key(h)}: ${r.reason}`)
      else assert.equal(r.reason, 'equivocation', `${key(last)} then ${key(h)}`)
    }
  }
})
