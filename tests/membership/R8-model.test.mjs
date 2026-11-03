// R8: membershipState agrees with the executable model (model/settled.mjs) on every state its explorer reaches in
// the pinned scenarios, and on sampled partial views of them (what a network attacker can choose to show).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { membership } from '../impl.mjs'
import { evaluate, reach, history, tick } from '../../model/settled.mjs'
import { translate, identityFor, letterOf, CTX_BASE } from './translate.mjs'

const { membershipState } = membership
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 100)

// The model's answer, in the form membershipState gives.
function modelAnswer (genesis, items, real) {
  const e = evaluate(genesis, items)
  if (e.dead) return { dead: true }
  return { dead: false, membership: real(e.record.id), settled: real(e.base.id), roots: [...e.record.roots].map((l) => l).sort(), pending: e.pending,
    authority: [...e.authority].sort(), frozen: e.frozen }
}

function implAnswer (genesis, items) {
  const { records, real } = translate(genesis, items)
  const r = membershipState(records, { ...CTX_BASE, identity: identityFor(genesis) })
  assert.equal(r.ok, true, JSON.stringify(r))
  if (r.dead) return { answer: { dead: true }, real }
  const letters = (ids) => ids.map(letterOf).sort()
  return { answer: { dead: false, membership: r.membership, settled: r.settled, roots: letters(r.roots), pending: r.pending,
    authority: letters(r.authority), frozen: r.frozen }, real }
}

function agree (genesis, items, label) {
  const { answer, real } = implAnswer(genesis, items)
  assert.deepEqual(answer, modelAnswer(genesis, items, real), label)
}

const SCENARIOS = [
  ['one root, stolen', [], ['a'], ['a']],
  ['two roots, later stolen', [['a', 'b']], ['a', 'b'], ['b']],
  ['three roots, later stolen', [['a', 'b', 'c']], ['a', 'b', 'c'], ['c']],
  ['three roots, first stolen', [['a', 'b', 'c']], ['a', 'b', 'c'], ['a']],
  ['three roots, two stolen', [['a', 'b', 'c']], ['a', 'b', 'c'], ['b', 'c']],
]

function states (epochs, roots, stolen) {
  const universe = [...roots, 'o', 't']
  const maxEpoch = epochs.length + 3
  const owner = new Set([...roots, 'o'])
  const thief = new Set([...stolen, 't'])
  const start = history('a', epochs)
  const thiefStates = reach('a', start, thief, universe, maxEpoch, 1)
  const out = new Map()
  for (const s of thiefStates) {
    // Every owner move that contests or freezes, and the first few others, to keep the run short.
    const count = (x, k) => x.filter((it) => it.kind === k).length
    const moves = reach('a', s, owner, universe, maxEpoch, 1)
    const picked = [...moves.filter((q) => count(q, 'C') > count(s, 'C') || count(q, 'F') > count(s, 'F')), ...moves.slice(0, 8)]
    for (const q of picked) {
      for (const x of [q, tick('a', tick('a', q))]) out.set(JSON.stringify(x), x)
    }
  }
  return [...out.values()]
}

const kinds = new Set()
for (const [name, epochs, roots, stolen] of SCENARIOS) {
  test(`${name}: agrees with the model on every explored state`, { timeout: 600_000 }, () => {
    const every = states(epochs, roots, stolen)
    assert.ok(every.length > 20, `explored ${every.length}`)
    // Under a small FC_RUNS (mutation testing), every k-th state and every dead or frozen one, deterministically.
    const stride = RUNS >= 100 ? 1 : Math.ceil(every.length / 40)
    const all = every.filter((x, i) => i % stride === 0 || evaluate('a', x).dead || evaluate('a', x).frozen)
    for (const items of all) {
      agree('a', items, JSON.stringify(items.filter((i) => i.kind !== 'T')).slice(0, 300))
      const e = evaluate('a', items)
      kinds.add(e.dead ? 'dead' : e.frozen ? 'frozen' : e.pending ? 'pending' : 'settled')
    }
  })
}

test('the scenarios together reach every kind of state (anti-vacuity)', () => {
  assert.deepEqual([...kinds].sort(), ['dead', 'frozen', 'pending', 'settled'])
})

test('agrees with the model on sampled partial views', { timeout: 600_000 }, () => {
  const all = SCENARIOS.flatMap(([, epochs, roots, stolen]) => states(epochs, roots, stolen))
  fc.assert(fc.property(fc.nat(all.length - 1), fc.array(fc.boolean(), { minLength: 40, maxLength: 40 }), (i, keep) => {
    const items = all[i].filter((it, j) => it.kind === 'T' || keep[j % 40])
    agree('a', items, `state ${i}`)
  }), { seed: SEED, numRuns: RUNS })
})
