// membershipState's answer for a model item set (model/settled.mjs), compared with the model's own answer.
import assert from 'node:assert/strict'
import { membership } from '../impl.mjs'
import { evaluate } from '../../model/settled.mjs'
import { translate, identityFor, letterOf, designation, CTX_BASE, BASE } from './translate.mjs'

const { membershipState } = membership

// The model's answer, in the form membershipState gives.
function modelAnswer (genesis, items, real) {
  const e = evaluate(genesis, items)
  if (e.dead) return { dead: true }
  return { dead: false, membership: real(e.record.id), settled: real(e.base.id), roots: [...e.record.roots].sort(), pending: e.pending,
    authority: [...e.authority].sort(), frozen: e.frozen, recovery: designation(e.base.rec) ?? null,
    recovering: e.notice ? { record: real(e.notice.id), at: BASE + e.notice.at } : null }
}

function implAnswer (genesis, items) {
  const { records, real } = translate(genesis, items)
  const r = membershipState(records, { ...CTX_BASE, identity: identityFor(genesis) })
  assert.equal(r.ok, true, JSON.stringify(r))
  if (r.dead) return { answer: { dead: true }, real }
  const letters = (ids) => ids.map(letterOf).sort()
  return { answer: { dead: false, membership: r.membership, settled: r.settled, roots: letters(r.roots), pending: r.pending,
    authority: letters(r.authority), frozen: r.frozen, recovery: JSON.parse(JSON.stringify(r.recovery)), recovering: r.recovering && { ...r.recovering } }, real }
}

export function agree (genesis, items, label) {
  const { answer, real } = implAnswer(genesis, items)
  assert.deepEqual(answer, modelAnswer(genesis, items, real), label)
}
