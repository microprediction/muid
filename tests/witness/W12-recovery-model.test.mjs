// R11: the witness agrees with the model's witness (model/settled.mjs), move by move, on random histories with
// recovery parties. The owner designates parties; then the owner, a thief holding one root, and the parties sign
// membership records, recoveries, cancels, contests and freezes, and time passes. Each record goes through admission;
// what is admitted is what the model is given, and everything the witness signs (anchors, settlements, notices,
// cancellations and maturities) is, text for text, the model's translated. The recovery under notice that verifiers
// read from what the witness holds is the model's.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { witness as modelWitness, moves, evaluate } from '../../model/settled.mjs'
import { translate, identityFor, rootText, TICK } from '../membership/translate.mjs'
import { membership } from '../impl.mjs'
import { witness } from './impl.mjs'
import { CONFIG, BASE, CTX_BASE, WITNESS } from './fixtures.mjs'
import { runs } from '../runs.mjs'

const PINNED = 20261113
const SEED = Number(process.env.FC_SEED ?? PINNED)
const USUAL = 120
const RUNS = runs(USUAL)
const G = 'a'
const I = identityFor(G)
// The model's tick is TICK seconds here, so that its windows (two or three ticks) are ones a designation may state,
// its contest window is one tick, and its cooling-off of two ticks is the witness's three days rounded up to a tick.
// A walk lasts longer than the shared fixtures' witness key: this one's window holds every tick of it.
const KEYS = Object.freeze([Object.freeze({ key: WITNESS, nbf: 0, exp: BASE + 1000 * TICK })])
const w = witness({ ...CONFIG, witnessKeys: KEYS, contestWindow: TICK })
const UNIVERSE = ['a', 'b', 'n', 'o']
const MAX_EPOCH = 5
const one = { parties: ['g'], k: 1, w: 2 }
const two = { parties: ['g', 'h'], k: 2, w: 2 }
const three = { parties: ['g', 'h', 'i'], k: 2, w: 3 }

const ticks = (items) => items.filter((it) => it.kind === 'T').length
const at = (items) => BASE + ticks(items) * TICK
const LIST = { M: ['memberships', 'membership'], C: ['contests', 'contest'], F: ['freezes', 'freeze'], X: ['cancels', 'cancel'] }
// The text of one model item, translated with the membership records before it.
function textOf (items, it) {
  const { records } = translate(G, [...items.filter((x) => x.kind === 'M'), it], TICK)
  const list = records[LIST[it.kind][0]]
  return { type: LIST[it.kind][1], text: list[list.length - 1] }
}
const witnessTexts = (items) => {
  const { records } = translate(G, items, TICK)
  return [...records.anchors, ...records.settlements, ...records.notices, ...records.cancelled, ...records.matured].sort()
}
// Of several records the model's witness could anchor or give notice of, the one with the least real id, as the witness.
const pickFor = (items) => (ids) => {
  const { real } = translate(G, items, TICK)
  return [...ids].sort((x, y) => (real(x) < real(y) ? -1 : 1))[0]
}
const sameRecord = (x, y) => x.n === y.n && x.prev === y.prev && x.roots.join() === y.roots.join() && JSON.stringify(x.rec ?? null) === JSON.stringify(y.rec ?? null)

function walk ([scenario, steps], reached) {
  const [roots, rec, stolen] = SCENARIOS[scenario]
  const holds = { owner: new Set([...roots, 'o']), thief: new Set([...stolen, 'o']), party: new Set(['g', 'h', 'n']) }
  let items = []
  let held = w.empty(I)
  const signed = []
  const trace = []
  const tryRoot = (l) => { const r = w.admit(held, 'root', rootText(l)); if (r.ok) held = r.held }
  tryRoot(G)

  // Submits a move's items until nothing more is admitted; what is refused is checked to change nothing.
  function submit (add) {
    let left = [...add]
    for (let progress = true; progress;) {
      progress = false
      for (const it of [...left]) {
        if (it.kind === 'M') for (const l of [it.signer, ...it.roots]) tryRoot(l)
        const { type, text } = textOf(items, it)
        const r = w.admit(held, type, text, it.kind === 'M' ? rootText(it.signer) : undefined)
        if (!r.ok) continue
        held = r.held
        // A signer's later proposal for one prev replaces its earlier one (R8's admission; a party's too).
        const replaced = (x) => x.kind === 'M' && it.kind === 'M' && x.signer === it.signer && x.prev === it.prev && !sameRecord(x, it)
        items = [...items.filter((x) => !replaced(x)), it]
        left = left.filter((x) => x !== it)
        progress = true
      }
    }
    for (const it of left) {
      const { type, text } = textOf(items, it)
      const reason = w.admit(held, type, text, it.kind === 'M' ? rootText(it.signer) : undefined).reason
      assert.ok(reason !== 'quota' && reason !== 'full', `refused (${reason}): the walk is too long for the model`)
      // The witness's own rules, which the model does not have: a withdrawn proposal stays withdrawn, and a signer is
      // held to a record whose majority, or whose parties' threshold, has signed.
      if (reason === 'replaced') continue
      if (reason === 'quorate') {
        assert.ok(items.some((x) => x.kind === 'M' && x.signer === it.signer && x.prev === it.prev && !sameRecord(x, it)), 'refused (quorate) with no proposal held')
        reached.add('held to a recovery')
        continue
      }
      const pick = pickFor(items)
      const said = (s) => JSON.stringify(s.filter((x) => 'ASNKU'.includes(x.kind)))
      assert.equal(said(modelWitness(G, [...items, it], pick)), said(modelWitness(G, items, pick)), `refused (${reason}) changes the witness: ${JSON.stringify(it)} after ${trace.join(' | ')}`)
      reached.add('refused')
    }
  }

  function step (label) {
    trace.push(label)
    items = modelWitness(G, items, pickFor(items))
    const r = w.advance(held, at(items))
    held = r.held
    for (const s of r.signed) signed.push(s.text)
    assert.deepEqual([...signed].sort(), witnessTexts(items), `after ${trace.join(' | ')}`)
    const e = evaluate(G, items)
    const s = membership.membershipState(held, { ...CTX_BASE, witnessKeys: KEYS, identity: I })
    assert.equal(s.ok, true)
    assert.equal(s.dead, e.dead)
    if (e.dead) { reached.add('dead'); return }
    const { real } = translate(G, items, TICK)
    assert.deepEqual([s.membership, s.settled, s.pending, s.recovering && { ...s.recovering }],
      [real(e.record.id), real(e.base.id), e.pending, e.notice && { record: real(e.notice.id), at: BASE + e.notice.at * TICK }], `state after ${trace.join(' | ')}`)
    const head = w.head(held, at(items))
    if (head !== undefined) assert.deepEqual(membership.headOf(s, at(items)).recovering, s.recovering ?? undefined)
    for (const [kind, name] of [['N', 'notice'], ['K', 'cancelled'], ['U', 'matured']]) if (items.some((x) => x.kind === kind)) reached.add(name)
    if (!e.pending && items.some((x) => x.kind === 'U' && x.id === e.record.id)) reached.add('recovered')
    if (e.pending) reached.add('pending')
  }

  // The owner designates, and the designation settles.
  const sorted = [...roots].sort()
  submit([...new Set([G, ...sorted])].map((signer) => ({ kind: 'M', n: 2, roots: sorted, prev: 'M1{a}<-', rec, signer })))
  step('designate')
  for (let i = 0; i < 2; i++) { items = [...items, { kind: 'T', k: ticks(items) }]; step('tick') }
  assert.deepEqual(evaluate(G, items).base.rec, rec, 'the designation has settled')

  for (const { actor, kind, choice } of steps) {
    if (actor === 'tick') {
      items = [...items, { kind: 'T', k: ticks(items) }]
      step('tick')
      continue
    }
    const all = moves(G, items, holds[actor], UNIVERSE, MAX_EPOCH, [one, null])
    const e = evaluate(G, items)
    // 'R': a successor of the last settled membership (for a party, a recovery of it); otherwise by kind of record.
    const near = all.filter((m) => !e.dead && (kind === 'R' ? m[0].kind === 'M' && m[0].prev === e.base.id : m[0].kind === kind))
    const from = near.length ? near : all
    if (from.length === 0) continue
    const add = from[choice % from.length]
    submit(add)
    step(`${actor} ${add.map((it) => JSON.stringify(it)).join(' ')}`)
  }
}

const SCENARIOS = [
  [['a'], one, ['a']],
  [['a', 'b'], one, ['b']],
  [['a', 'b'], two, ['b']],
  [['a', 'b'], three, ['a']],
]
const step = fc.record({
  actor: fc.constantFrom('party', 'party', 'party', 'owner', 'thief', 'tick', 'tick', 'tick', 'tick'),
  kind: fc.constantFrom('R', 'R', 'X', 'X', 'M', 'C', 'F'),
  choice: fc.nat(),
})
const WALK = fc.tuple(fc.nat(SCENARIOS.length - 1), fc.array(step, { minLength: 1, maxLength: 12 }))

// At the usual count from the pinned seed the walks must reach notices, cancellations, maturity, a completed
// recovery, a dead identity, refusals and a party held to its recovery (anti-vacuity); a lower count (mutation
// testing) or another seed (the nightly run) is not held to that.
test('with recovery parties, the witness signs what the model\'s witness does, and verifiers read the same recovery under notice', { timeout: 1_200_000 }, () => {
  const reached = new Set()
  fc.assert(fc.property(WALK, (walk1) => walk(walk1, reached)), { seed: SEED, numRuns: RUNS })
  if (RUNS >= USUAL && SEED === PINNED) {
    assert.deepEqual([...reached].sort(), ['cancelled', 'dead', 'held to a recovery', 'matured', 'notice', 'pending', 'recovered', 'refused'])
  }
})
