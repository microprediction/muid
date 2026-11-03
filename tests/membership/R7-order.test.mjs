// R7: the state depends on the set of records only. Permuting each list, repeating records and mixing in another
// identity's records leave it unchanged, in a settled, a frozen pending and a dead scenario.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { membership } from '../impl.mjs'
import { history, witness } from '../../model/settled.mjs'
import { translate, identityFor, CTX_BASE } from './translate.mjs'

const { membershipState } = membership
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 100)
const KINDS = ['roots', 'memberships', 'contests', 'freezes', 'anchors', 'settlements']
const ctx = { ...CTX_BASE, identity: identityFor('a') }
const plain = (r) => JSON.stringify(r)

const twoEpochs = history('a', [['a', 'b'], ['a', 'b', 'c']])
const settled2 = history('a', [['a', 'b']])
const prev = settled2.find((it) => it.kind === 'S').outcome
const proposal = (roots) => roots.map((signer) => ({ kind: 'M', n: 3, roots, prev, signer }))
const pending = witness('a', [...settled2, ...proposal(['a', 'b', 'c'])])
const SCENARIOS = [
  ['settled at epoch 3', twoEpochs, (s) => s.epoch === 3 && !s.pending && !s.dead],
  ['pending epoch 3, frozen', [...pending, { kind: 'F', target: `M3{a,b,c}<${prev}`, signer: 'c' }], (s) => s.pending && s.frozen],
  ['two anchored rivals: dead', [...pending, ...proposal(['a', 'b', 'd']), { kind: 'A', id: `M3{a,b,d}<${prev}`, at: 2 }], (s) => s.dead],
]
// Another identity's records, valid for that identity: they must change nothing here.
const FOREIGN = translate('e', history('e', [['d', 'e']])).records

const permutation = (n) => fc.array(fc.nat(), { minLength: n, maxLength: n }).map((keys) =>
  keys.map((k, i) => [k, i]).sort((x, y) => x[0] - y[0] || x[1] - y[1]).map(([, i]) => i))

for (const [name, items, shape] of SCENARIOS) {
  const { records } = translate('a', items)
  const original = membershipState(records, ctx)

  test(`${name}: the scenario is as named`, () => {
    assert.equal(original.ok, true)
    assert.ok(shape(original), plain(original))
  })

  test(`${name}: permuted, repeated and mixed with another identity's records, the state is unchanged`, () => {
    const lists = fc.record(Object.fromEntries(KINDS.map((k) => [k, fc.record({
      order: permutation(records[k].length),
      repeats: fc.array(fc.nat({ max: Math.max(records[k].length - 1, 0) }), { maxLength: 3 }),
      foreign: fc.boolean(),
    })])))
    let mixed = 0
    fc.assert(fc.property(lists, (spec) => {
      const shown = {}
      for (const k of KINDS) {
        const { order, repeats, foreign } = spec[k]
        const list = order.map((i) => records[k][i])
        for (const i of repeats) if (records[k].length > 0) list.splice(i % (list.length + 1), 0, records[k][i])
        if (foreign && FOREIGN[k].length > 0) {
          list.splice(order.length % (list.length + 1), 0, ...FOREIGN[k])
          mixed++
        }
        shown[k] = list
      }
      assert.equal(plain(membershipState(shown, ctx)), plain(original))
    }), { seed: SEED, numRuns: RUNS })
    assert.ok(mixed > RUNS / 2, 'most runs include foreign records')
  })
}
