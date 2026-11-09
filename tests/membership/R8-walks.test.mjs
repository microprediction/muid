// R8 beyond the explorer's bound: random walks of up to eight moves, each by the thief, the owner, the witness clock
// or a lying witness, from the pinned scenarios. After every move membershipState must give the model's answer
// (model/settled.mjs), and so must a partial view of the final state; no view of the witness service's own items may
// show a forked membership. A lying witness (a stolen witness key) shows verifiers anchors and settlements of its
// choosing: the verifier must still refuse a record without its majority, a contest without one, and two anchored
// rivals. The explorer (R8-model) covers one thief move and one owner answer exhaustively; these walks reach later
// epochs, contests after freezes and moves after settlement, sampled. The nightly fuzz job runs them at many times
// the count.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { evaluate, history, moves, witness, tick, forkedView, contestId } from '../../model/settled.mjs'
import { payloadsOf } from '../../model/recovery.mjs'
import { agree } from './agree.mjs'
import { runs } from '../runs.mjs'

const PINNED = 20261109
const SEED = Number(process.env.FC_SEED ?? PINNED)
const USUAL = 200
const RUNS = runs(USUAL)

const SCENARIOS = [
  [[], ['a'], ['a']],
  [[['a', 'b']], ['a', 'b'], ['b']],
  [[['a', 'b', 'c']], ['a', 'b', 'c'], ['c']],
  [[['a', 'b', 'c']], ['a', 'b', 'c'], ['a']],
  [[['a', 'b', 'c']], ['a', 'b', 'c'], ['b', 'c']],
]

// A move: the clock ticks, an actor signs, or the witness lies. `kind` chooses among an actor's moves by the kind of
// record (memberships far outnumber the rest): 'N' is a membership following the last settled one (a rival while one
// is pending), 'C' a contest of the effective record where there is one; `choice` chooses among those.
const step = fc.record({
  actor: fc.constantFrom('thief', 'thief', 'owner', 'owner', 'tick', 'tick', 'liar'),
  kind: fc.constantFrom('M', 'N', 'C', 'F'),
  choice: fc.nat(),
})
const WALK = [fc.nat(SCENARIOS.length - 1), fc.array(step, { minLength: 1, maxLength: 8 }),
  fc.array(fc.boolean(), { minLength: 40, maxLength: 40 })]

// What a lying witness can sign now, as a stolen witness key could: an anchor on a membership record (for 'M' and
// 'N') or a contest ('C') it has not anchored, or a settlement of a record's predecessor to that record or to
// 'contested' ('F'). Its forgeries go only to verifiers: the witness service never sees them and keeps its own log.
function lies (seen, kind) {
  const at = seen.filter((it) => it.kind === 'T').length
  const anchored = new Set(seen.filter((it) => it.kind === 'A').map((it) => it.id))
  const payloads = [...payloadsOf(seen).values()]
  const anchor = (ids) => ids.filter((id) => !anchored.has(id)).map((id) => [{ kind: 'A', id, at }])
  if (kind === 'C') return anchor([...new Set(seen.filter((it) => it.kind === 'C').map((it) => contestId(it.record)))])
  if (kind === 'F') return payloads.flatMap((p) => [p.id, 'contested'].map((outcome) => [{ kind: 'S', prev: p.prev, outcome, at }]))
  return anchor(payloads.map((p) => p.id))
}

// One walk. `check` compares the verifier with the model on what verifiers see; `reached` records what the walk got to.
function walk ([scenario, steps, keep], check, reached) {
  const [epochs, roots, stolen] = SCENARIOS[scenario]
  const universe = [...roots, 'o', 't']
  const maxEpoch = epochs.length + 4
  const holds = { owner: new Set([...roots, 'o']), thief: new Set([...stolen, 't']) }
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
      // An even choice signs every anchor of the kind at once.
      const add = choice % 2 === 0 && kind !== 'F' ? from.flat() : from[(choice >> 1) % from.length]
      forged = [...forged, ...add]
      trace.push(`liar ${add.map((it) => JSON.stringify(it)).join(' ')}`)
    } else {
      const all = moves('a', s, holds[actor], universe, maxEpoch)
      const e = evaluate('a', s)
      const near = (m) => !e.dead && (kind === 'N'
        ? m[0].kind === 'M' && m[0].prev === e.base.id
        : m[0].kind === 'C' && m[0].record === e.record.id)
      const nearby = kind === 'N' || kind === 'C' ? all.filter(near) : []
      const some = nearby.length ? nearby : all.filter((m) => m[0].kind === (kind === 'N' ? 'M' : kind))
      const from = some.length ? some : all
      if (from.length === 0) continue
      const add = from[choice % from.length]
      s = witness('a', [...s, ...add])
      trace.push(`${actor} ${add.map((it) => JSON.stringify(it)).join(' ')}`)
    }
    const seen = [...s, ...forged]
    check(seen, `scenario ${scenario}: ${trace.join(' | ')}`)
    const e = evaluate('a', seen)
    reached.kinds.add(e.dead ? 'dead' : e.frozen ? 'frozen' : e.pending ? 'pending' : 'settled')
    if (!e.dead) reached.epochs = Math.max(reached.epochs, e.record.n - epochs.length - 1)
    reached.steps = Math.max(reached.steps, trace.length)
    if (forged.length) reached.lies++
  }
  const seen = [...s, ...forged]
  check(seen.filter((it, j) => it.kind === 'T' || keep[j % keep.length]), `scenario ${scenario}, partial view: ${trace.join(' | ')}`)
  let forked = null
  try { forked = forkedView('a', s) } catch { /* more groups than the exhaustive views allow */ }
  assert.equal(forked, null, `scenario ${scenario}: the witness service's items have a forked view after ${trace.join(' | ')}`)
}

const fresh = () => ({ kinds: new Set(), epochs: 0, steps: 0, lies: 0 })

test('random walks agree with the model after every move, and the witness service forks no view', { timeout: 1_200_000 }, () => {
  const reached = fresh()
  fc.assert(fc.property(...WALK, (...w) => walk(w, (items, label) => agree('a', items, label), reached)),
    { seed: SEED, numRuns: RUNS })
})

// The walk generator, sampled at the usual count from the pinned seed and run through the model alone (no records
// signed, so it holds at any FC_RUNS): it must reach every kind of state, two epochs past the scenario's history,
// eight moves, and lies.
test('the walk generator reaches every kind of state, two further epochs, eight moves and lies (anti-vacuity)', () => {
  const reached = fresh()
  for (const w of fc.sample(fc.tuple(...WALK), { seed: PINNED, numRuns: USUAL })) walk(w, () => {}, reached)
  assert.deepEqual([...reached.kinds].sort(), ['dead', 'frozen', 'pending', 'settled'])
  assert.ok(reached.epochs >= 2, `epochs past the history: ${reached.epochs}`)
  assert.equal(reached.steps, 8)
  assert.ok(reached.lies > USUAL / 2, `states after a lie: ${reached.lies}`)
})
