// R8, one field at a time: in a state where a record of each type matters, a variant of it (re-signed, so only the
// field differs) is ignored, and each R1–R5 boundary is pinned.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { membership, envelope } from '../impl.mjs'
import { identityFor, CTX_BASE, rootId, rootText, rootSigned, witnessSigned, BASE } from './translate.mjs'

const { membershipState } = membership
const I = identityFor('a')
const ctx = { ...CTX_BASE, identity: I }
const ids = (...letters) => letters.map(rootId).sort()
const mid = (body) => envelope.seal('membership', body).id
const sign = (body, ...letters) => letters.map((l) => rootSigned('membership', body, l))
const anchor = (record, at = BASE + 1, identity = I) => witnessSigned('anchor', { identity, record, at })
const settle = (prev, outcome, at = BASE + 2, identity = I) => witnessSigned('settlement', { identity, prev, outcome, at })
const state = (records) => JSON.parse(JSON.stringify(membershipState(records, ctx)))

// Epoch 2 = {a, b}, settled; epoch 3 = {a, b, c}, pending.
const e2 = { identity: I, prev: I, epoch: 2, roots: ids('a', 'b') }
const e3 = { identity: I, prev: mid(e2), epoch: 3, roots: ids('a', 'b', 'c') }
const roots = ['a', 'b', 'c', 'd', 'e', 'o'].map(rootText)
const settledE2 = { roots, memberships: sign(e2, 'a', 'b'), anchors: [anchor(mid(e2))], settlements: [settle(I, mid(e2))] }
const pendingE3 = { ...settledE2, memberships: [...settledE2.memberships, ...sign(e3, 'a', 'b', 'c')], anchors: [...settledE2.anchors, anchor(mid(e3), BASE + 3)] }

test('controls: epoch 2 settled; epoch 3 pending', () => {
  assert.equal(state(settledE2).epoch, 2)
  assert.deepEqual([state(pendingE3).epoch, state(pendingE3).pending], [3, true])
})

test('anchor variants are ignored: extra key, another identity, a bad time, an id with junk', () => {
  const base = { ...settledE2, settlements: [] } // pending on the anchor alone
  assert.equal(state(base).pending, true)
  for (const [name, a] of [
    ['extra key', witnessSigned('anchor', { identity: I, record: mid(e2), at: BASE + 1, x: 1 })],
    ['another identity', anchor(mid(e2), BASE + 1, '9'.repeat(64))],
    ['negative at', anchor(mid(e2), -1)],
    ['string at', witnessSigned('anchor', { identity: I, record: mid(e2), at: String(BASE) })],
    ['boolean at', witnessSigned('anchor', { identity: I, record: mid(e2), at: true })],
    ['record with a suffix', anchor(mid(e2) + '0')],
    ['record with a prefix', anchor('x' + mid(e2))],
  ]) {
    assert.equal(state({ ...base, anchors: [a] }).epoch, 1, name)
  }
  assert.equal(state({ ...base, anchors: [anchor(mid(e2), 0)] }).epoch, 2, 'at = 0 is a time')
})

test('settlement variants are ignored, so the change stays pending', () => {
  for (const [name, s] of [
    ['extra key', witnessSigned('settlement', { identity: I, prev: I, outcome: mid(e2), at: BASE + 2, x: 1 })],
    ['another identity', settle(I, mid(e2), BASE + 2, '9'.repeat(64))],
    ['bad at', settle(I, mid(e2), -1)],
    ['prev not an id', settle('x', mid(e2))],
    ['outcome not an id', settle(I, 'x')],
    ['outcome empty', settle(I, '')],
  ]) {
    assert.deepEqual([state({ ...settledE2, settlements: [s] }).epoch, state({ ...settledE2, settlements: [s] }).pending], [2, true], name)
  }
})

test('settlements: contested, or two outcomes, end the identity; an outcome off the chain is stale', () => {
  assert.equal(state({ ...settledE2, settlements: [settle(I, 'contested')] }).dead, true, 'contested')
  assert.equal(state({ ...settledE2, settlements: [...settledE2.settlements, settle(I, mid(e3))] }).dead, true, 'two outcomes')
  const off = { identity: I, prev: mid(e3), epoch: 2, roots: ids('a', 'b') }
  const r = state({ ...settledE2, memberships: [...sign(off, 'a', 'b')], anchors: [], settlements: [settle(I, mid(off))] })
  assert.deepEqual([r.epoch, r.pending], [1, false], 'the settled outcome does not follow from the identity: stale')
})

test('R1: exactly half is not a majority; five roots, all signing, are accepted; six never', () => {
  const half = { identity: I, prev: mid(e2), epoch: 3, roots: ids('a', 'c') }
  assert.equal(state({ ...settledE2, memberships: [...settledE2.memberships, ...sign(half, 'a', 'c')], anchors: [...settledE2.anchors, anchor(mid(half), BASE + 3)] }).epoch, 2)
  const five = { identity: I, prev: I, epoch: 2, roots: ids('a', 'b', 'c', 'd', 'e') }
  assert.equal(state({ roots, memberships: sign(five, 'a', 'b', 'c', 'd', 'e'), anchors: [anchor(mid(five))] }).epoch, 2)
  const six = { identity: I, prev: I, epoch: 2, roots: ids('a', 'b', 'c', 'd', 'e', 'o') }
  assert.equal(state({ roots, memberships: sign(six, 'a', 'b', 'c', 'd', 'e', 'o'), anchors: [anchor(mid(six))] }).epoch, 1)
})

test('an anchored membership whose prev is not on the chain is ignored', () => {
  const stray = { identity: I, prev: '7'.repeat(64), epoch: 2, roots: ids('a', 'b') }
  assert.equal(state({ roots, memberships: sign(stray, 'a', 'b'), anchors: [anchor(mid(stray))] }).epoch, 1)
})

test('contests (R5): a strict majority of the base, anchored, while pending; variants are ignored', () => {
  const contest = (body, ...letters) => letters.map((l) => rootSigned('contest', body, l))
  const cid = (body) => envelope.seal('contest', body).id
  const c = { identity: I, record: mid(e3) }
  const with_ = (texts, body) => ({ ...pendingE3, contests: texts, anchors: [...pendingE3.anchors, anchor(cid(body), BASE + 4)] })
  assert.equal(state(with_(contest(c, 'a', 'b'), c)).dead, true, 'majority: ends the identity')
  assert.equal(state(with_(contest(c, 'a'), c)).dead, false, 'one of two is not a majority')
  assert.equal(state({ ...pendingE3, contests: contest(c, 'a', 'b') }).dead, false, 'not anchored')
  for (const [name, body] of [['extra key', { ...c, x: 1 }], ['another identity', { ...c, identity: '9'.repeat(64) }], ['record not an id', { identity: I, record: 'x' }]]) {
    assert.equal(state(with_(contest(body, 'a', 'b'), body)).dead, false, name)
  }
})

test('freezes: by a root of the membership; variants are ignored; a freeze of the settled base holds while pending', () => {
  const freeze = (body, letter) => rootSigned('freeze', body, letter)
  const f = { identity: I, membership: mid(e2) }
  assert.equal(state({ ...settledE2, freezes: [freeze(f, 'a')] }).frozen, true)
  assert.equal(state({ ...settledE2, freezes: [freeze(f, 'c')] }).frozen, false, 'c is not in epoch 2')
  assert.equal(state({ ...pendingE3, freezes: [freeze(f, 'b')] }).frozen, true, 'base frozen while pending')
  for (const [name, body] of [['extra key', { ...f, x: 1 }], ['another identity', { ...f, identity: '9'.repeat(64) }], ['membership not an id', { identity: I, membership: 'x' }]]) {
    assert.equal(state({ ...settledE2, freezes: [freeze(body, 'a')] }).frozen, false, name)
  }
})

test('inputs that are not records objects give exact reasons; contexts are checked field by field', () => {
  for (const records of [undefined, null, 1, 'x']) assert.deepEqual({ ...membershipState(records, ctx) }, { ok: false, reason: 'unknown-identity' }, String(records))
  assert.deepEqual({ ...membershipState({ roots: 'x' }, ctx) }, { ok: false, reason: 'unknown-identity' })
  for (const c of [{ ...ctx, origin: 1 }, { ...ctx, identity: I + '0' }, { ...ctx, identity: 'x' + I.slice(1) + '0' }, { ...ctx, identity: [I] }]) {
    assert.throws(() => membershipState({}, c), { name: 'TypeError' })
  }
})

test('a text that is not a record, in any list, is ignored', () => {
  for (const k of ['roots', 'memberships', 'contests', 'freezes', 'anchors', 'settlements']) {
    assert.equal(state({ ...settledE2, [k]: [...settledE2[k] ?? [], 'x', 5, null] }).epoch, 2, k)
  }
})

test('envelopes from a signer already counted for a record are not verified again (bounded work)', async () => {
  const { make } = await import('../assertion/helpers.mjs')
  const { secretOf } = await import('./translate.mjs')
  const { payload, id } = envelope.seal('membership', e2)
  // Distinct texts, same record and signer: each assertion carries a different counter, so each verifies alone.
  const variants = Array.from({ length: 250 }, (_, i) => envelope.wrap(payload, { root: rootId('b'),
    assertion: make({ covers: [id], secret: secretOf('b'), ad: authDataWithCount(i) }) }))
  // Relative, so load on the machine scales both sides: the fastest of three runs each way.
  const fastest = (records) => Math.min(...[0, 1, 2].map(() => { const t0 = performance.now(); assert.equal(state(records).epoch, 2); return performance.now() - t0 }))
  const plain = fastest(settledE2)
  const redundant = fastest({ ...settledE2, memberships: [...settledE2.memberships, ...variants].slice(0, 252) })
  assert.ok(redundant < 15 * plain, `250 redundant signatures: ${redundant.toFixed(1)} ms against ${plain.toFixed(1)} ms plain`)
})

function authDataWithCount (count) {
  return Buffer.concat([createHash('sha256').update('id.example').digest(), Buffer.from([0x1d]), Buffer.from([0, 0, count >> 8, count & 255])])
}
