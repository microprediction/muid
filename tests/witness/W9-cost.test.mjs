// Found by review: every submission, even one refused, replayed the identity's whole history (R8, every signature
// verified again), inside its queue: a keyless flood of refused requests held the owner's own requests up. A holding
// is immutable, so its state is computed once and kept with it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { w, start, M2, signed, rootText, admitAll } from './fixtures.mjs'

// A holding whose `anchors` reads are counted: R8's replay reads them, admission's own checks do not.
function counted (held) {
  const n = { reads: 0 }
  return { n, held: new Proxy(held, { get (t, k) { if (k === 'anchors') n.reads++; return t[k] } }) }
}

test("a holding's state is replayed once, however many submissions are decided against it", () => {
  const base = w.advance(admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')]]), 1_800_000_000).held
  const { n, held } = counted(base)
  // Refused: another identity's record, then a membership record the holding already has (accepted unchanged), then
  // one signed by a root that is not a root here.
  const first = w.admit(held, 'membership', signed('membership', M2, 'c'))
  assert.equal(first.ok, false)
  const once = n.reads
  assert.ok(once > 0, 'the state was replayed')
  for (let i = 0; i < 20; i++) {
    assert.equal(w.admit(held, 'membership', signed('membership', M2, 'c')).ok, false)
    assert.equal(w.admit(held, 'membership', signed('membership', M2, 'a')).ok, true)
  }
  assert.equal(n.reads, once, 'not replayed again')
})
