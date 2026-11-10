// R8: records of the wrong shape are ignored; a witness that anchors two records for one prev ends the identity; a
// records object that throws when read is refused.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { membership, envelope } from '../impl.mjs'
import { history } from '../../model/settled.mjs'
import { translate, identityFor, CTX_BASE, rootId, rootText, rootSigned, witnessSigned, BASE } from './translate.mjs'

const { membershipState } = membership
const ctx = { ...CTX_BASE, identity: identityFor('a') }
const { records } = translate('a', history('a', [['a', 'b']]))
const identity = identityFor('a')
const base = membershipState(records, ctx)
const same = (extra, label) => assert.deepEqual(JSON.parse(JSON.stringify(membershipState({ ...records, ...extra }, ctx))),
  JSON.parse(JSON.stringify(base)), label)

test('control: the two-root history settles at epoch 2', () => assert.equal(base.epoch, 2))

test('memberships of the wrong shape are ignored, however they are signed', () => {
  const ab = [rootId('a'), rootId('b')].sort()
  const bodies = [
    { identity, prev: identity, epoch: 2, roots: ab, extra: 1 },
    { identity, prev: identity, epoch: 2, roots: [] },
    { identity, prev: identity, epoch: 2, roots: [...ab, ...['1', '2', '3', '4'].map((c) => c.repeat(64))].sort() },
    { identity, prev: identity, epoch: 2, roots: [...ab].reverse() },
    { identity, prev: identity, epoch: 2, roots: [ab[0], ab[0]] },
    { identity, prev: identity, epoch: 2, roots: [ab[0], 'x'] },
    { identity, prev: identity, epoch: 2, roots: 'ab' },
    { identity, prev: identity, epoch: 3, roots: ab },
    { identity: '9'.repeat(64), prev: identity, epoch: 2, roots: ab },
    { identity, prev: 'x', epoch: 2, roots: ab },
  ]
  for (const body of bodies) {
    const texts = ['a', 'b'].map((l) => rootSigned('membership', body, l))
    const { id } = envelope.seal('membership', body)
    const anchor = witnessSigned('anchor', { identity, record: id, at: BASE + 50 })
    // Offered on its own, with an anchor, instead of the real history: never a valid next membership.
    const r = membershipState({ ...records, memberships: texts, anchors: [anchor], settlements: [] }, ctx)
    assert.equal(r.epoch, 1, JSON.stringify(body).slice(0, 80))
  }
})

test('witness records of the wrong shape, and root-signed records whose sig is not { assertion, root }, are ignored', () => {
  const real = JSON.parse(records.anchors[0])
  same({ anchors: [...records.anchors, envelope.wrap(real.payload, { signature: 'ab', witness: 'cd' })] }, 'bad witness sig')
  const m = JSON.parse(records.memberships[0])
  same({ memberships: [...records.memberships, envelope.wrap(m.payload, { ...m.sig, extra: 1 })] }, 'extra sig key')
  same({ anchors: [witnessSigned('anchor', { identity, record: '1'.repeat(64), at: -1 }), ...records.anchors] }, 'bad at')
  same({ settlements: [witnessSigned('settlement', { identity, prev: identity, outcome: 'nope', at: BASE }), ...records.settlements] }, 'bad outcome')
  same({ contests: [rootSigned('contest', { identity, record: 'x' }, 'a')] }, 'contest of a non-id')
  same({ freezes: [rootSigned('freeze', { identity, membership: 'x' }, 'a')] }, 'freeze of a non-id')
})

test('a witness that anchors two valid records for one prev ends the identity', () => {
  const one = { identity, prev: identity, epoch: 2, roots: [rootId('a'), rootId('c')].sort() }
  const two = { identity, prev: identity, epoch: 2, roots: [rootId('a'), rootId('d')].sort() }
  const signed = [rootSigned('membership', one, 'a'), rootSigned('membership', one, 'c'), rootSigned('membership', two, 'a'), rootSigned('membership', two, 'd')]
  const anchors = [one, two].map((b) => witnessSigned('anchor', { identity, record: envelope.seal('membership', b).id, at: BASE + 1 }))
  const roots = ['a', 'c', 'd'].map(rootText)
  assert.equal(membershipState({ roots, memberships: signed, anchors: anchors.slice(0, 1) }, ctx).epoch, 2, 'one anchored: pending')
  assert.deepEqual({ ...membershipState({ roots, memberships: signed, anchors }, ctx) }, { ok: true, dead: true })
})

test('a records object that throws when read is refused, never thrown', () => {
  const hostile = { get roots () { throw new Error('getter') } }
  assert.deepEqual({ ...membershipState(hostile, ctx) }, { ok: false, reason: 'records' })
  const proxy = new Proxy({}, { get () { throw new Error('trap') } })
  assert.deepEqual({ ...membershipState(proxy, ctx) }, { ok: false, reason: 'records' })
})

test('cost is bounded: duplicates are verified once, and each list is capped', () => {
  const copies = Array.from({ length: 200 }, () => records.memberships[0])
  const t0 = performance.now()
  same({ memberships: [...records.memberships, ...copies] }, '200 duplicate envelopes change nothing')
  assert.ok(performance.now() - t0 < 500, `took ${Math.round(performance.now() - t0)} ms`)
  const tooMany = Array.from({ length: membership.MAX_RECORDS + 1 }, (_, i) => 'x' + i)
  assert.deepEqual({ ...membershipState({ ...records, anchors: tooMany }, ctx) }, { ok: false, reason: 'records' })
  assert.equal(membershipState({ ...records, anchors: tooMany.slice(1) }, ctx).epoch, 2, 'at the cap: accepted')
  const huge = new Proxy([], { get: (t, k) => (k === 'length' ? 1e9 : Reflect.get(t, k)) })
  const t1 = performance.now()
  assert.deepEqual({ ...membershipState({ ...records, contests: huge }, ctx) }, { ok: false, reason: 'records' })
  assert.ok(performance.now() - t1 < 100, 'refused without walking it')
  // A length that is not an array length is refused before any element is read, however it compares: an object whose
  // valueOf says 0 to the cap and 5,000 afterwards, NaN, a fraction, a negative, Infinity, a string (found by review).
  let calls = 0
  const shifty = { valueOf: () => (++calls === 1 ? 0 : 5000) }
  for (const length of [shifty, NaN, 1.5, -1, Infinity, '3', 2 ** 53]) {
    let read = 0
    const lying = new Proxy([], { get: (t, k) => (k === 'length' ? length : (read++, Reflect.get(t, k))) })
    assert.deepEqual({ ...membershipState({ ...records, roots: lying }, ctx) }, { ok: false, reason: 'records' }, String(length))
    assert.equal(read, 0, `no element read under a length of ${String(length)}`)
  }
})
