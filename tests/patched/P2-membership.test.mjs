// §4 residual for membership (tests/patched/sweep.mjs): under any one patched built-in, membershipState gives the
// state it gives unpatched, or fails closed (refused, or a throw). The cases are real signed records translated from
// the model's items: a settled change, a pending one, a frozen membership, a contested change, and two forgeries by
// a lying witness (an anchor on a record half the roots signed, and anchors on two rivals).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { membership } from '../impl.mjs'
import { history, witness, tick } from '../../model/settled.mjs'
import { genesisOf, membershipId } from '../../model/recovery.mjs'
import { translate, identityFor, CTX_BASE } from '../membership/translate.mjs'
import { sweep } from './sweep.mjs'

const g = genesisOf('a').id
const M2 = membershipId(2, ['a', 'b', 'c'], g)
const signedBy = (n, roots, prev, signers) => signers.map((signer) => ({ kind: 'M', n, roots, prev, signer }))
const settled = history('a', [['a', 'b', 'c']])
const pending = witness('a', [...settled, ...signedBy(3, ['a', 'b', 'd'], M2, ['a', 'b', 'd'])])
const SETS = [
  ['settled', settled],
  ['pending', pending],
  ['frozen', witness('a', [...settled, { kind: 'F', target: M2, signer: 'c' }])],
  ['contested', witness('a', [...pending, ...['a', 'b'].map((signer) => ({ kind: 'C', record: membershipId(3, ['a', 'b', 'd'], M2), signer }))])],
  ['half signed, anchored by a liar', [...settled, ...signedBy(3, ['a', 't'], M2, ['a', 't']), { kind: 'A', id: membershipId(3, ['a', 't'], M2), at: 9 }]],
  ['two rivals anchored', [...pending, ...signedBy(3, ['a', 'b'], M2, ['a', 'b']), { kind: 'A', id: membershipId(3, ['a', 'b'], M2), at: 9 }]],
  ['settled after its window', tick('a', tick('a', pending))],
]
const CASES = SETS.map(([name, items]) => {
  const { records } = translate('a', items)
  const ctx = { ...CTX_BASE, identity: identityFor('a') }
  return { name, run: () => membership.membershipState(records, ctx) }
})
// Captured: describe runs while a built-in, JSON.stringify among them, is patched.
const stringify = JSON.stringify
const describe = (r) => stringify(r === null || typeof r !== 'object' ? r
  : { ok: r.ok, reason: r.reason, dead: r.dead, membership: r.membership, settled: r.settled, epoch: r.epoch, roots: r.roots, authority: r.authority, pending: r.pending, frozen: r.frozen })

test('no patched built-in changes the membership state, except by failing closed', () => {
  const { base, changed, failedClosed } = sweep(CASES, describe, (r) => JSON.parse(r).ok === false)
  const kinds = base.map((b) => JSON.parse(b))
  assert.ok(kinds.every((k) => k.ok === true), 'unpatched, every case is read')
  assert.deepEqual(kinds.map((k) => k.dead ? 'dead' : k.frozen ? 'frozen' : k.pending ? 'pending' : 'settled'),
    ['settled', 'pending', 'frozen', 'dead', 'settled', 'dead', 'settled'])
  assert.deepEqual(changed, [])
  assert.ok(failedClosed >= 20, `only ${failedClosed} results failed closed`)
})
