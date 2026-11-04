// The witness agrees with the model's witness (model/settled.mjs), move by move, on random histories: owner and
// thief sign membership records, contests and freezes, and time passes. Each record goes through admission; what is
// admitted is what the model is given, and the anchors and settlements the witness signs are, text for text, the
// model's translated. A record admission refuses changes nothing the model's witness or verifier would do with it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { witness as modelWitness, moves, evaluate } from '../../model/settled.mjs'
import { translate, identityFor, rootText } from '../membership/translate.mjs'
import { witness } from './impl.mjs'
import { CONFIG, BASE } from './fixtures.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261104)
const RUNS = Number(process.env.FC_RUNS ?? 100)
const G = 'a'
const w = witness({ ...CONFIG, contestWindow: 1 }) // the model's window is one tick
const UNIVERSE = ['a', 'b', 'c', 't']
const MAX_EPOCH = 4

const now = (items) => items.filter((it) => it.kind === 'T').length
const ws = (items) => items.filter((it) => it.kind === 'A' || it.kind === 'S')
// The text of one model item, translated with the items before it.
function textOf (items, it) {
  const { records } = translate(G, [...items.filter((x) => x.kind === 'M'), it])
  const list = { M: records.memberships, C: records.contests, F: records.freezes }[it.kind]
  return { type: { M: 'membership', C: 'contest', F: 'freeze' }[it.kind], text: list[list.length - 1] }
}
const witnessTexts = (items) => {
  const { records } = translate(G, items)
  return [...records.anchors, ...records.settlements].sort()
}
// The model picks, of several valid successors, the one with the lowest real id, as the witness does.
const pickFor = (items) => (ids) => {
  const { real } = translate(G, items)
  return [...ids].sort((x, y) => (real(x) < real(y) ? -1 : 1))[0]
}
const summary = (e) => (e.dead ? 'dead' : `${e.record.id} ${e.pending} ${e.frozen} ${[...e.authority].sort()}`)

function walk (steps, owner, thief) {
  let items = []
  let held = w.empty(identityFor(G))
  const tryRoot = (l) => { const r = w.admit(held, 'root', rootText(l)); if (r.ok) held = r.held }
  tryRoot(G)
  let kinds = 0
  for (const n of steps) {
    if (n % 4 === 0) {
      items = [...items, { kind: 'T', k: now(items) }]
    } else {
      const options = moves(G, items, n % 2 ? owner : thief, UNIVERSE, MAX_EPOCH)
      if (options.length === 0) continue
      // Passes until nothing more is admitted: an added root's signature waits for a majority of the previous roots,
      // and its root record for a held record that names it (R8).
      let left = [...options[(n >> 2) % options.length]]
      for (let progress = true; progress;) {
        progress = false
        for (const it of [...left]) {
          if (it.kind === 'M') for (const l of [it.signer, ...it.roots]) tryRoot(l)
          const { type, text } = textOf(items, it)
          const r = w.admit(held, type, text)
          if (!r.ok) continue
          held = r.held
          items = [...items, it]
          left = left.filter((x) => x !== it)
          progress = true
        }
      }
      for (const it of left) {
        // Refused: the model's witness and verifier do exactly the same with it as without it.
        const pick = pickFor(items)
        const reason = w.admit(held, textOf(items, it).type, textOf(items, it).text).reason
        assert.deepEqual(ws(modelWitness(G, [...items, it], pick)), ws(modelWitness(G, items, pick)), `refused (${reason}) changes the witness`)
        assert.equal(summary(evaluate(G, [...items, it])), summary(evaluate(G, items)), `refused (${reason}) changes the state`)
        kinds |= 1
      }
    }
    items = modelWitness(G, items, pickFor(items))
    const r = w.advance(held, BASE + now(items))
    held = r.held
    assert.deepEqual([...held.anchors, ...held.settlements].sort(), witnessTexts(items), `after ${steps.join(',')}`)
    const e = evaluate(G, items)
    if (r.signed.length > 0) kinds |= 2
    if (!e.dead && e.pending) kinds |= 8
  }
  return kinds
}

const SCENARIOS = [
  ['an owner with every root, a thief with none', new Set(['a', 'b', 'c']), new Set(['t'])],
  ['a thief holding one of the owner\'s roots', new Set(['a', 'b', 'c']), new Set(['b', 't'])],
  ['a thief holding the first root', new Set(['a', 'b', 'c']), new Set(['a', 't'])],
]

for (const [name, owner, thief] of SCENARIOS) {
  test(`${name}: the witness signs what the model's witness does`, { timeout: 600_000 }, () => {
    let seen = 0
    fc.assert(fc.property(fc.array(fc.nat(), { minLength: 1, maxLength: 14 }), (steps) => { seen |= walk(steps, owner, thief) }),
      { seed: SEED, numRuns: RUNS >= 100 ? RUNS : Math.ceil(RUNS / 3) }) // fewer under mutation testing
    assert.equal(seen & 2, 2, 'the witness signed something')
    assert.equal(seen & 1, 1, 'admission refused something')
    assert.equal(seen & 8, 8, 'a change was pending')
  })
}
