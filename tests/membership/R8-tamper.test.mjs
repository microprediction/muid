// Tamper sweep on the witness's side: a one-character change to any one of an identity's records leaves its state as
// it is with that record, or as it is without it, and never anything else (a tampered record carries no authority).
// Positions are sampled with a fixed seed; MUID_SWEEP=full sweeps every position (a long run, not gating).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { membership } from '../impl.mjs'
import { history, witness } from '../../model/settled.mjs'
import { translate, identityFor, CTX_BASE } from './translate.mjs'

const { membershipState } = membership
const ctx = { ...CTX_BASE, identity: identityFor('a') }
const FULL = process.env.MUID_SWEEP === 'full'
const PER_RECORD = 40

// Settled at epoch 2 {a, b}; epoch 3 {a, b, c} anchored and pending; a freeze of the pending record by c.
const settled = history('a', [['a', 'b']])
const prev = settled.find((it) => it.kind === 'S').outcome
const items = witness('a', [...settled,
  ...['a', 'b', 'c'].map((signer) => ({ kind: 'M', n: 3, roots: ['a', 'b', 'c'], prev, signer }))])
const { records, real } = translate('a', [...items, { kind: 'F', target: `M3{a,b,c}<${prev}`, signer: 'c' }])
const plain = (r) => JSON.parse(JSON.stringify(r))
const ORIGINAL = plain(membershipState(records, ctx))

// A deterministic generator, so a failure names a position that reproduces.
function * positions (length, seed) {
  if (FULL) {
    for (let i = 0; i < length; i++) yield i
    return
  }
  let x = seed
  for (let k = 0; k < PER_RECORD; k++) {
    x = (Math.imul(x, 1_103_515_245) + 12_345) >>> 0
    yield x % length
  }
}

function variants (text, seed) {
  const out = []
  for (const i of positions(text.length, seed)) {
    const ch = text[i]
    out.push([i, text.slice(0, i) + String.fromCharCode(ch.charCodeAt(0) ^ 1) + text.slice(i + 1)])
    out.push([i, text.slice(0, i) + (ch === '0' ? '1' : '0') + text.slice(i + 1)])
    out.push([i, text.slice(0, i) + text.slice(i + 1)])
  }
  return out
}

test('the scenario: epoch 3 pending over a settled epoch 2, frozen by a root of the pending record', () => {
  assert.equal(ORIGINAL.ok, true)
  assert.equal(ORIGINAL.epoch, 3)
  assert.equal(ORIGINAL.pending, true)
  assert.equal(ORIGINAL.frozen, true)
  assert.equal(ORIGINAL.membership, real(`M3{a,b,c}<${prev}`))
  // Each kind holds a record whose loss changes the state, so "with or without" is a real constraint.
  for (const k of ['roots', 'memberships', 'anchors', 'settlements', 'freezes']) {
    const differs = records[k].some((_, n) =>
      JSON.stringify(plain(membershipState({ ...records, [k]: records[k].filter((_, j) => j !== n) }, ctx))) !== JSON.stringify(ORIGINAL))
    assert.ok(differs, k)
  }
})

for (const kind of ['roots', 'memberships', 'anchors', 'settlements', 'freezes']) {
  test(`a one-character change to any of the ${kind} gives the state with or without that record`, () => {
    let checked = 0
    records[kind].forEach((text, n) => {
      const without = plain(membershipState({ ...records, [kind]: records[kind].filter((_, j) => j !== n) }, ctx))
      for (const [i, t] of variants(text, 1 + n)) {
        const got = plain(membershipState({ ...records, [kind]: records[kind].map((x, j) => (j === n ? t : x)) }, ctx))
        const same = JSON.stringify(got)
        assert.ok(same === JSON.stringify(ORIGINAL) || same === JSON.stringify(without), `${kind}[${n}] at ${i}: ${same}`)
        checked++
      }
    })
    assert.ok(checked >= records[kind].length * 3 * Math.min(PER_RECORD, 100))
  })
}
