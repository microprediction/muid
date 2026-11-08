// Decision 10 against the model: over every history the explorer reaches with an honest witness (an actor holding
// every root makes every move, and the clock ticks), no head is refused as equivocation after any head the witness
// signed earlier on the same history, and none shown after a later one is called equivocation: heads of one second
// may come in either order. Heads from histories that diverge (what a lying witness could show two relying parties)
// are refused in part. Every distinct honest pair, both ways round, and a sample of diverging ones are replayed
// through the real verifier. Heads carry revocations as R10 has the witness choose them: one revoked delegation for each
// membership the head names and each root with authority (every such pair has a logged delegation, revoked), so a
// membership change within one second drops entries an earlier head of that second carried.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { evaluate, moves, witness, tick, setKey } from '../../model/settled.mjs'
import { genesisOf } from '../../model/recovery.mjs'
import { verifier as verifierModule, envelope } from '../impl.mjs'
import { make, RP_ID, ORIGIN } from '../assertion/helpers.mjs'
import { identityFor, rootId, rootText, secretOf } from '../membership/translate.mjs'

const G = 'a'
const SCENARIOS = [[['a', 'b'], 3, 5], [['a', 'b', 'c'], 3, 4]]

// The head the honest witness signs for an item set (R9): none for a dead or frozen identity or one without authority.
// Its revocations (R10) are those naming a live logged delegation: under a membership it names, by a root with authority.
function headOf (items) {
  const e = evaluate(G, items)
  if (e.dead || e.frozen || e.authority.length === 0) return null
  const memberships = e.pending ? [e.base.id, e.record.id] : [e.base.id]
  const authority = [...e.authority].sort()
  const revoked = memberships.flatMap((m) => authority.map((r) => `${m} ${r}`)).sort()
  return { epoch: e.base.n, memberships, authority, revoked, at: items.filter((it) => it.kind === 'T').length }
}
const key = (h) => JSON.stringify(h)

// SPEC decision 10, stated over epochs and sets, apart from src/verifier.js: can an honest witness sign `h` after `l`?
function consistent (l, h) {
  const epochs = (x) => x.memberships.map((m, i) => [x.epoch + i, m])
  const top = (x) => x.epoch + x.memberships.length - 1
  if (h.epoch < l.epoch || top(h) < top(l)) return false
  // Within one second, under the same memberships, the witness only adds revocations.
  if (h.at === l.at && h.epoch === l.epoch && key(h.memberships) === key(l.memberships) && !l.revoked.every((x) => h.revoked.includes(x))) return false
  for (const [e, m] of epochs(l)) for (const [f, n] of epochs(h)) if ((e === f) !== (m === n)) return false
  const sub = (a, b) => a.every((r) => b.includes(r))
  const turnsPending = h.epoch === l.epoch && h.memberships.length > l.memberships.length
  const settlesAlone = h.epoch === l.epoch + 1 && l.memberships.length === 2 && h.memberships.length === 1
  if (h.epoch === l.epoch && !turnsPending) return sub(h.authority, l.authority) && sub(l.authority, h.authority)
  if (turnsPending) return sub(h.authority, l.authority)
  return !settlesAlone || sub(l.authority, h.authority)
}

// Every state reachable in `depth` steps, each with the heads signed before it on some history leading to it.
function explore (universe, maxEpoch, depth) {
  const holds = new Set(universe)
  const states = new Map([['', { items: [], parents: new Set() }]])
  let frontier = ['']
  for (let d = 0; d < depth; d++) {
    const next = []
    for (const k of frontier) {
      const { items } = states.get(k)
      const succ = moves(G, items, holds, universe, maxEpoch).map((add) => witness(G, [...items, ...add]))
      succ.push(tick(G, items))
      for (const s of succ) {
        const sk = setKey(s)
        if (!states.has(sk)) { states.set(sk, { items: s, parents: new Set() }); next.push(sk) }
        states.get(sk).parents.add(k)
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
    for (const p of s.parents) {
      const ps = states.get(p)
      for (const [hk, h] of ps.before) s.before.set(hk, h)
      if (ps.head) s.before.set(key(ps.head), ps.head)
    }
  }
  const honest = new Map()
  for (const s of states.values()) if (s.head) for (const last of s.before.values()) honest.set(key([last, s.head]), [last, s.head])
  const heads = new Map()
  for (const s of states.values()) if (s.head) heads.set(key(s.head), s.head)
  return { states: states.size, honest: [...honest.values()], heads: [...heads.values()] }
}

const results = SCENARIOS.map(([universe, maxEpoch, depth]) =>
  ({ name: `${universe.join(', ')}; epochs to ${maxEpoch}; ${depth} steps`, ...explore(universe, maxEpoch, depth) }))

for (const { name, states, honest, heads } of results) {
  test(`${name}: every head an honest witness signs later is consistent with every earlier one`, () => {
    const kinds = new Set()
    for (const [last, h] of honest) {
      assert.ok(last.at <= h.at, 'heads are signed in time order')
      assert.equal(consistent(last, h), true, `${key(last)} then ${key(h)}`)
      kinds.add(`${h.epoch - last.epoch}${last.memberships.length}${h.memberships.length}`)
    }
    assert.ok(states > 1000 && honest.length > 300, `states ${states}, distinct honest pairs ${honest.length}`)
    // Anti-vacuity: the honest pairs include each progression the rule distinguishes, and changes of authority.
    for (const k of ['011', '012', '022', '121', '122', '111', '221']) assert.ok(kinds.has(k), `progression ${k} reached`)
    assert.ok(honest.some(([l, h]) => key(l.authority) !== key(h.authority)), 'authority changes between honest heads')
    assert.ok(honest.some(([l, h]) => l.at === h.at && !l.revoked.every((x) => h.revoked.includes(x))),
      'an honest head of one second drops a revocation an earlier one carried')
  })

  test(`${name}: heads from diverging histories are refused in part`, () => {
    let flagged = 0
    for (const a of heads) for (const b of heads) if (a.at <= b.at && !consistent(a, b)) flagged++
    assert.ok(heads.length > 20 && flagged > 20, `heads ${heads.length}, flagged ${flagged}`)
  })
}

// Replay through the real verifier: model memberships become hex ids (the genesis is the identity), roots are the
// model's passkeys, heads are signed by a pinned witness key, and the delegation is made under the presented head's
// settled membership by a root with authority in it.
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_000
const W = Uint8Array.from({ length: 32 }, (_, i) => 3 + i)
const APP = Uint8Array.from({ length: 32 }, (_, i) => 90 + i)
const AUD = 'https://app.example'
const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD,
  witnessKeys: [{ key: hex(ed25519.getPublicKey(W)), nbf: 0, exp: NOW + 1000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
const I = identityFor(G)
const idOf = (m) => (m === genesisOf(G).id ? I : createHash('sha256').update(m).digest('hex'))
const memo = new Map()
const once = (k, f) => { if (!memo.has(k)) memo.set(k, f()); return memo.get(k) }
const delegationFor = (membership, letter) => once(`d ${membership} ${letter}`, () => {
  const { payload, id } = envelope.seal('delegation', { identity: I, membership, root: rootId(letter),
    subject: hex(ed25519.getPublicKey(APP)), aud: AUD, scopes: ['post'], nbf: NOW - 100, exp: NOW + 1000 })
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  return envelope.wrap(payload, { root: make({ covers: [id], secret: secretOf(letter) }), subject })
})
const revokedId = (x) => createHash('sha256').update('revoked ' + x).digest('hex')
const signed = (h) => once(`h ${key(h)}`, () => {
  const { payload } = envelope.seal('head', { identity: I, epoch: h.epoch, memberships: h.memberships.map(idOf),
    authority: h.authority.map(rootId).sort(), revoked: h.revoked.map(revokedId).sort(), at: NOW - 100 + h.at })
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), W)), witness: hex(ed25519.getPublicKey(W)) })
})
// R10: the witness's logged record of a delegation.
const loggedOf = (text) => once(`l ${text}`, () => {
  const { payload } = envelope.seal('logged', { identity: I, delegation: envelope.open(text, 'delegation').id, at: NOW - 100 })
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), W)), witness: hex(ed25519.getPublicKey(W)) })
})
function verify (last, h) {
  const letter = h.authority[0]
  const delegation = delegationFor(idOf(h.memberships[0]), letter)
  const r = v.verifyDelegation({ delegation, root: rootText(letter), head: signed(h), logged: loggedOf(delegation) },
    { now: NOW, scope: 'post', revoked: [], lastHead: signed(last) })
  return r.ok ? 'ok' : r.reason
}

test('the real verifier: honest pairs accepted in order and stale reversed; diverging pairs are equivocation', () => {
  const { honest, heads } = results[1]
  let reversedSameSecond = 0
  for (const [last, h] of honest) {
    assert.equal(verify(last, h), 'ok', `${key(last)} then ${key(h)}`)
    if (key(last) === key(h)) continue
    assert.equal(verify(h, last), 'stale', `${key(h)} then the earlier ${key(last)}`)
    if (last.at === h.at) reversedSameSecond++
  }
  assert.ok(reversedSameSecond > 10, `honest pairs of one second, reversed: ${reversedSameSecond}`)
  // Diverging: a later head inconsistent with an earlier one, or two heads of one second inconsistent both ways round.
  const diverging = []
  for (const a of heads) {
    for (const b of heads) {
      if (a.at < b.at ? !consistent(a, b) : a.at === b.at && !consistent(a, b) && !consistent(b, a)) diverging.push([a, b])
    }
  }
  const step = Math.max(1, Math.floor(diverging.length / 300))
  const sample = diverging.filter((_, i) => i % step === 0)
  assert.ok(sample.length >= 300 && diverging.some(([a, b]) => a.at === b.at), `diverging ${diverging.length}`)
  for (const [last, h] of sample) assert.equal(verify(last, h), 'equivocation', `${key(last)} then ${key(h)}`)
})

// The relying-party adapter keeps a head accepted after the stored one of its second (SPEC F5): sound because no two
// heads that differ can each follow the other, by the rule restated and through the real verifier.
test('two different heads of one second are never each able to follow the other', () => {
  let pairs = 0
  for (const { heads } of results) {
    for (const a of heads) {
      for (const b of heads) {
        if (a.at !== b.at || key(a) === key(b)) continue
        pairs++
        assert.ok(!(consistent(a, b) && consistent(b, a)), `${key(a)} and ${key(b)}`)
      }
    }
  }
  assert.ok(pairs > 1000, `pairs of one second: ${pairs}`)
  for (const a of results[1].heads) {
    for (const b of results[1].heads) {
      if (a.at === b.at && key(a) !== key(b)) assert.ok(verify(a, b) !== 'ok' || verify(b, a) !== 'ok', `${key(a)} and ${key(b)}`)
    }
  }
})
