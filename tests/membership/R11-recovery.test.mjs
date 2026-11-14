// R11 (recovery parties) in membershipState, against the executable model (model/settled.mjs) as its oracle: the
// model's own scenarios step by step, every partial view of them, and random walks in which the owner, a thief, the
// parties, the clock and a lying witness all move. After every move the verifier must give the model's answer: the
// membership, who has authority, the designation, and the recovery under notice.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { evaluate, history, moves, witness, tick, forkedView } from '../../model/settled.mjs'
import { membershipId, genesisOf, payloadsOf, RMAX } from '../../model/recovery.mjs'
import { agree } from './agree.mjs'
import { runs } from '../runs.mjs'

const PINNED = 20261113
const SEED = Number(process.env.FC_SEED ?? PINNED)
const USUAL = 150
const RUNS = runs(USUAL)
const G = genesisOf('a').id
const one = { parties: ['g'], k: 1, w: 2 }
const two = { parties: ['g', 'h'], k: 2, w: 2 }
const self = { parties: ['b', 'g'], k: 2, w: 2 } // b is a root of the membership that names it

// Every subset of the items, a record's signatures apart: what any verifier might hold.
function views (items, check) {
  const rest = items.filter((it) => it.kind !== 'T')
  assert.ok(rest.length <= 14, `too many items for every view: ${rest.length}`)
  for (let mask = 0; mask < 1 << rest.length; mask++) check(rest.filter((_, i) => mask & (1 << i)), `view ${mask}`)
}

const signed = (n, roots, prev, rec, signers) => signers.map((signer) => (rec ? { kind: 'M', n, roots, prev, rec, signer } : { kind: 'M', n, roots, prev, signer }))

for (const [name, rec, parties] of [['one party', one, ['g']], ['two parties of two', two, ['g', 'h']]]) {
  test(`${name}: designated, under notice, cancelled, asked again, matured and settled, the verifier agrees with the model at each step and in every view`, () => {
    const m2 = membershipId(2, ['a'], G, rec)
    let s = history('a', [{ roots: ['a'], rec }])
    const steps = []
    const step = (label, next) => { s = next; steps.push(label); agree('a', s, steps.join(', ')) }
    step('designated', s)
    assert.deepEqual(evaluate('a', s).base.rec, rec)
    // The first party alone, where two are needed, is no recovery.
    const r1 = signed(3, ['n'], m2, rec, [...parties, 'n'])
    if (parties.length > 1) {
      step('one of two signed', witness('a', [...s, r1[0]]))
      assert.equal(evaluate('a', s).notice, null)
    }
    step('asked', witness('a', [...s, ...r1]))
    assert.notEqual(evaluate('a', s).notice, null)
    step('cancelled', witness('a', [...s, { kind: 'X', record: membershipId(3, ['n'], m2, rec), signer: 'a' }]))
    assert.equal(evaluate('a', s).notice, null)
    views(s, (v, label) => agree('a', v, `${steps.join(', ')}: ${label}`))
    // Another recovery, after the cooling-off, left alone.
    const r2 = signed(3, ['i', 'n'], m2, rec, [...parties, 'i', 'n'])
    step('asked again', tick('a', tick('a', witness('a', [...s, ...r2]))))
    assert.equal(evaluate('a', s).notice?.id, membershipId(3, ['i', 'n'], m2, rec))
    for (let i = 0; i < RMAX; i++) step('a tick', tick('a', s))
    const e = evaluate('a', s)
    assert.ok(!e.pending && e.record.id === membershipId(3, ['i', 'n'], m2, rec) && e.authority.join() === 'i,n', 'recovered and settled')
    // A verifier with the recovery, its anchor and settlement but not the witness's `matured` is behind, never ahead.
    agree('a', s.filter((it) => it.kind !== 'U'), 'without matured')
  })
}

test('a recovery matured and settled: every view of it agrees with the model', () => {
  const m2 = membershipId(2, ['a'], G, one)
  let s = witness('a', [...history('a', [{ roots: ['a'], rec: one }]), ...signed(3, ['n'], m2, null, ['g', 'n'])])
  for (let i = 0; i <= RMAX; i++) s = tick('a', s)
  assert.equal(evaluate('a', s).record.id, membershipId(3, ['n'], m2, null))
  // The honest history before the designation is given whole; the rest in every subset.
  const before = s.filter((it) => it.kind === 'M' && it.n === 2)
  const after = s.filter((it) => !before.includes(it))
  views(after, (v, label) => agree('a', [...before, ...v], label))
})

test('a party that is a root of the membership naming it is no party: it does not count toward the threshold beside a real one', () => {
  const m2 = membershipId(2, ['a', 'b'], G, self)
  const base = history('a', [{ roots: ['a', 'b'], rec: self }])
  // b alone, one root of two and a named party: no recovery, in the model and the verifier, even anchored and called
  // matured by a witness that lies.
  const id = membershipId(3, ['n'], m2, null)
  const lie = [{ kind: 'N', id, at: 9 }, { kind: 'U', id, at: 9 }, { kind: 'A', id, at: 9 }]
  const byRoot = [...witness('a', [...base, ...signed(3, ['n'], m2, null, ['b', 'n'])]), ...lie]
  assert.equal(evaluate('a', byRoot).record.id, m2)
  agree('a', byRoot, 'a root as its own party')
  views([...signed(3, ['n'], m2, null, ['b', 'n']), ...lie], (v, label) => agree('a', [...base, ...v], label))
  // Two are needed, and the root is not one: with the real party's signature too, still no recovery.
  const both = [...witness('a', [...base, ...signed(3, ['n'], m2, null, ['b', 'g', 'n'])]), ...lie]
  assert.equal(evaluate('a', both).record.id, m2)
  agree('a', both, 'the root and the real party')
  views([...signed(3, ['n'], m2, null, ['b', 'g', 'n']), ...lie].slice(0, 6), (v, label) => agree('a', [...base, ...v], label))
})

// Random walks. The owner holds the roots and a fresh one; the thief one stolen root and a fresh one; the parties
// their own keys and a fresh root to restore the identity to. A lying witness shows verifiers notices, cancellations,
// maturities, anchors and settlements of its choosing.
const SCENARIOS = [
  [[{ roots: ['a'], rec: one }], ['a'], ['a']],
  [[{ roots: ['a', 'b'], rec: one }], ['a', 'b'], ['b']],
  [[{ roots: ['a', 'b'], rec: two }], ['a', 'b'], ['b']],
  [[{ roots: ['a', 'b'], rec: self }], ['a', 'b'], ['a']],
  [[['a', 'b', 'c']], ['a', 'b', 'c'], ['c']],
]
const step = fc.record({
  actor: fc.constantFrom('thief', 'owner', 'party', 'party', 'party', 'tick', 'tick', 'tick', 'tick', 'tick', 'liar'),
  kind: fc.constantFrom('M', 'R', 'X', 'C', 'F'),
  choice: fc.nat(),
})
const WALK = [fc.nat(SCENARIOS.length - 1), fc.array(step, { minLength: 1, maxLength: 12 }), fc.array(fc.boolean(), { minLength: 40, maxLength: 40 })]

function lies (seen, kind) {
  const at = seen.filter((it) => it.kind === 'T').length
  const have = new Set(seen.filter((it) => 'ANKU'.includes(it.kind)).map((it) => it.kind + it.id))
  const payloads = [...payloadsOf(seen).values()]
  const say = (k) => payloads.filter((p) => !have.has(k + p.id)).map((p) => [{ kind: k, id: p.id, at }])
  if (kind === 'R') return [...say('N'), ...say('U')]
  if (kind === 'X') return say('K')
  if (kind === 'F') return payloads.flatMap((p) => [p.id, 'contested'].map((outcome) => [{ kind: 'S', prev: p.prev, outcome, at }]))
  // A recovery anchored together with the lie that it matured, or any record anchored.
  return [...say('A'), ...payloads.filter((p) => !have.has('A' + p.id)).map((p) => [{ kind: 'U', id: p.id, at }, { kind: 'A', id: p.id, at }])]
}

function walk ([scenario, steps, keep], check, reached) {
  const [epochs, roots, stolen] = SCENARIOS[scenario]
  const universe = [...roots, 'o', 'n']
  const maxEpoch = epochs.length + 3
  const holds = { owner: new Set([...roots, 'o']), thief: new Set([...stolen, 't']), party: new Set(['g', 'h', 'n']) }
  let s = history('a', epochs)
  let forged = []
  const trace = []
  for (const { actor, kind, choice } of steps) {
    if (actor === 'tick') {
      s = tick('a', s)
      trace.push('tick')
    } else if (actor === 'liar') {
      const from = lies([...s, ...forged], kind)
      if (from.length === 0) continue
      const add = from[choice % from.length]
      forged = [...forged, ...add]
      trace.push(`liar ${add.map((it) => JSON.stringify(it)).join(' ')}`)
    } else {
      const all = moves('a', s, holds[actor], universe, maxEpoch, [one, null])
      const e = evaluate('a', s)
      // 'R': a membership following the last settled one (for a party, a recovery of it).
      const near = all.filter((m) => !e.dead && (kind === 'R' ? m[0].kind === 'M' && m[0].prev === e.base.id : m[0].kind === kind))
      const from = near.length ? near : all
      if (from.length === 0) continue
      const add = from[choice % from.length]
      s = witness('a', [...s, ...add])
      trace.push(`${actor} ${add.map((it) => JSON.stringify(it)).join(' ')}`)
    }
    const seen = [...s, ...forged]
    check(seen, `scenario ${scenario}: ${trace.join(' | ')}`)
    const e = evaluate('a', seen)
    const own = evaluate('a', s)
    if (!own.dead && own.notice) reached.add('notice')
    if (s.some((it) => it.kind === 'K')) reached.add('cancelled')
    if (s.some((it) => it.kind === 'U')) reached.add('matured')
    if (!own.dead && !own.pending && s.some((it) => it.kind === 'U' && it.id === own.record.id)) reached.add('recovered')
    if (forged.length && !e.dead && e.notice && !(own.notice && own.notice.id === e.notice.id)) reached.add('forged notice')
    reached.add(e.dead ? 'dead' : e.frozen ? 'frozen' : e.pending ? 'pending' : 'settled')
  }
  const seen = [...s, ...forged]
  check(seen.filter((it, j) => it.kind === 'T' || keep[j % keep.length]), `scenario ${scenario}, partial view: ${trace.join(' | ')}`)
  let forked = null
  try { forked = forkedView('a', s) } catch { /* more groups than the exhaustive views allow */ }
  assert.equal(forked, null, `scenario ${scenario}: the witness's items have a forked view after ${trace.join(' | ')}`)
}

test('random walks with recovery parties agree with the model after every move, and the witness forks no view', { timeout: 1_200_000 }, () => {
  const reached = new Set()
  fc.assert(fc.property(...WALK, (...w) => walk(w, (items, label) => agree('a', items, label), reached)), { seed: SEED, numRuns: RUNS })
})

test('the walk generator reaches notices, cancellations, maturity, a completed recovery, forged notices and every kind of state (anti-vacuity)', () => {
  const reached = new Set()
  for (const w of fc.sample(fc.tuple(...WALK), { seed: PINNED, numRuns: USUAL })) walk(w, () => {}, reached)
  assert.deepEqual([...reached].sort(), ['cancelled', 'dead', 'forged notice', 'frozen', 'matured', 'notice', 'pending', 'recovered', 'settled'])
})
