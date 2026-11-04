// Found by review (round 8): admission let one root fill a list with distinct envelopes of the same records, let a
// root without authority add revocations through delegations it signed, and let one assertion propose a change and
// contest it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope } from '../impl.mjs'
import { make } from '../assertion/helpers.mjs'
import { secretOf } from '../membership/translate.mjs'
import { w, IDENTITY, BASE, WINDOW, start, M2, mBody, mId, signed, covering, contestId, rootId, rootText, admitAll, state } from './fixtures.mjs'

const refused = (r) => (r.ok ? 'accepted' : r.reason)
const hex = (b) => Buffer.from(b).toString('hex')
const junk = (i) => (i + 1).toString(16).padStart(64, '0')

// {a, b, c} settled at epoch 2.
function settledABC () {
  const M = mBody(2, ['a', 'b', 'c'], IDENTITY)
  const h = admitAll(start(), [['membership', signed('membership', M, 'a')], ['root', rootText('b')], ['root', rootText('c')],
    ['membership', signed('membership', M, 'b')], ['membership', signed('membership', M, 'c')]])
  return { M, held: w.advance(w.advance(h, BASE).held, BASE + WINDOW).held }
}

test('one envelope per record and signer: others for the same record are accepted unchanged', () => {
  let h = start()
  for (let i = 0; i < 60; i++) {
    const r = w.admit(h, 'membership', covering('membership', M2, 'a', [junk(i)]))
    assert.equal(r.ok, true)
    h = r.held
  }
  assert.equal(h.memberships.length, 1)
})

test("one proposal per root and prev: a root's later proposal replaces its earlier one, so a stolen root cannot fill the list", () => {
  const { M, held } = settledABC()
  let h = held
  // The thief holds c, and proposes 40 changes (each admitted; the list does not grow).
  for (let i = 0; i < 40; i++) h = w.admit(h, 'membership', signed('membership', { ...mBody(3, ['c'], mId(M)), roots: [rootId('c'), junk(i)].sort() }, 'c')).held
  assert.equal(h.memberships.length, held.memberships.length + 1, "only the thief's last proposal is held")
  // The owner's recovery, by a and b, is admitted and anchored; c's lone proposal is not.
  const R = mBody(3, ['a', 'b'], mId(M))
  h = admitAll(h, [['membership', signed('membership', R, 'a')], ['membership', signed('membership', R, 'b')]])
  const a = w.advance(h, BASE + 2 * WINDOW)
  assert.deepEqual(a.signed.map((x) => envelope.open(x.text, 'anchor').body.record), [mId(R)])
  // An owner may change its mind: a's new proposal replaces its old one.
  const S = mBody(3, ['a'], mId(M))
  const changed = w.admit(admitAll(held, [['membership', signed('membership', R, 'a')]]), 'membership', signed('membership', S, 'a')).held
  assert.deepEqual(changed.memberships.slice(held.memberships.length).map((t) => envelope.open(t, 'membership').id), [mId(S)])
})

test('one envelope per contest and freeze and signer', () => {
  const pending = w.advance(admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')],
    ['membership', signed('membership', M2, 'b')]]), BASE).held
  let h = pending
  for (let i = 0; i < 60; i++) {
    h = w.admit(h, 'contest', covering('contest', { identity: IDENTITY, record: mId(M2) }, 'a', [junk(i)])).held
    h = w.admit(h, 'freeze', covering('freeze', { identity: IDENTITY, membership: IDENTITY }, 'a', [junk(i)])).held
  }
  assert.equal(h.contests.length, 1)
  assert.equal(h.freezes.length, 1)
})

test('W0: one assertion cannot both propose a change and contest it, in either order', () => {
  // The proposal's assertion also covers its own contest: refused.
  assert.equal(refused(w.admit(start(), 'membership', covering('membership', M2, 'a', [contestId(mId(M2))]))), 'covers')
  // The contest's assertion also covers the record it contests: refused.
  const pending = w.advance(admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')],
    ['membership', signed('membership', M2, 'b')]]), BASE).held
  assert.equal(refused(w.admit(pending, 'contest', covering('contest', { identity: IDENTITY, record: mId(M2) }, 'a', [mId(M2)]))), 'covers')
  // Covering other records (delegations, say) is allowed.
  assert.equal(w.admit(pending, 'contest', covering('contest', { identity: IDENTITY, record: mId(M2) }, 'a', [junk(1)])).ok, true)
  assert.equal(w.admit(start(), 'membership', covering('membership', M2, 'a', [junk(1)])).ok, true)
})

test("a self-revocation counts only under a delegation from a root with authority (R6): a retired root's do not", () => {
  // Epoch 2 = {b}: a is retired.
  const M = mBody(2, ['b'], IDENTITY)
  const settled = w.advance(w.advance(admitAll(start(), [['membership', signed('membership', M, 'a')], ['root', rootText('b')],
    ['membership', signed('membership', M, 'b')]]), BASE).held, BASE + WINDOW).held
  assert.deepEqual(state(settled).authority, [rootId('b')])
  const now = BASE + WINDOW + 10
  const key = Uint8Array.from({ length: 32 }, (_, i) => 90 + i)
  const subject = hex(ed25519.getPublicKey(key))
  const delegationBy = (letter) => {
    const body = { identity: IDENTITY, membership: mId(M), root: rootId(letter), subject, aud: 'https://app.example', scopes: ['post'], nbf: now - 10, exp: now + 3600 }
    const { payload, id } = envelope.seal('delegation', body)
    return envelope.wrap(payload, { root: make({ covers: [id], secret: secretOf(letter) }),
      subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), key)) })
  }
  const { payload } = envelope.seal('revocation', { identity: IDENTITY, target: subject, at: now })
  const rev = envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), key)) })
  assert.equal(refused(w.revoke(settled, rev, now, delegationBy('a'))), 'delegation')
  assert.equal(w.revoke(settled, rev, now, delegationBy('b')).ok, true)
})

// Found by review (round 9): root records named only by a replaced proposal stayed held, so one root could fill the
// roots list and block every later root addition; and W0 was applied to a record's own contest only.
test('a root record named only by a replaced proposal is dropped with it, so the roots list stays bounded', () => {
  const { M, held } = settledABC()
  let h = held
  // The thief (root c) cycles proposals, each naming a fresh root whose record it submits.
  for (const l of ['d', 'e', 'o', 't']) {
    const P = mBody(3, ['c', l], mId(M))
    h = admitAll(h, [['membership', signed('membership', P, 'c')], ['root', rootText(l)]])
  }
  assert.equal(h.roots.length, held.roots.length + 1, 'only the root its last proposal names')
  assert.deepEqual(h.roots.slice(held.roots.length), [rootText('t')])
  // The owner can still add a root.
  const R = mBody(3, ['a', 'b', 'd'], mId(M))
  h = admitAll(h, [['membership', signed('membership', R, 'a')], ['membership', signed('membership', R, 'b')], ['root', rootText('d')],
    ['membership', signed('membership', R, 'd')]])
  assert.deepEqual(w.advance(h, BASE + 2 * WINDOW).signed.map((x) => envelope.open(x.text, 'anchor').body.record), [mId(R)])
  // Roots of settled memberships, and the first root, are never dropped.
  assert.ok(h.roots.includes(rootText('a')) && h.roots.includes(rootText('c')))
})

test('W0, as SPEC states it: one assertion cannot propose a successor and contest the pending record, either way', () => {
  const pending = w.advance(admitAll(start(), [['membership', signed('membership', M2, 'a')], ['root', rootText('b')],
    ['membership', signed('membership', M2, 'b')]]), BASE).held
  const M3 = mBody(3, ['a', 'b'], mId(M2))
  // A successor of the pending record whose assertion also covers the pending record's contest: refused.
  assert.equal(refused(w.admit(pending, 'membership', covering('membership', M3, 'a', [contestId(mId(M2))]))), 'covers')
  // A contest whose assertion also covers a held successor of the record it contests: refused.
  const withM3 = admitAll(pending, [['membership', covering('membership', M3, 'b', [junk(1)])]])
  assert.equal(refused(w.admit(withM3, 'contest', covering('contest', { identity: IDENTITY, record: mId(M2) }, 'a', [mId(M3)]))), 'covers')
  // A contest whose assertion covers other records, a held successor among them only if named, is admitted.
  assert.equal(w.admit(withM3, 'contest', covering('contest', { identity: IDENTITY, record: mId(M2) }, 'a', [junk(1)])).ok, true)
  // And a held membership that is not a successor of the contested record may be covered too.
  const { M, held } = settledABC()
  const R = mBody(3, ['a', 'b'], mId(M))
  const pendingR = w.advance(admitAll(held, [['membership', signed('membership', R, 'a')], ['membership', signed('membership', R, 'b')]]), BASE + 2 * WINDOW).held
  assert.equal(w.admit(pendingR, 'contest', covering('contest', { identity: IDENTITY, record: mId(R) }, 'a', [mId(M)])).ok, true)
  // And the other order: a held contest whose assertion covers a successor refuses that successor's envelope.
  const withContest = admitAll(pending, [['contest', covering('contest', { identity: IDENTITY, record: mId(M2) }, 'a', [mId(M3)])]])
  assert.equal(refused(w.admit(withContest, 'membership', covering('membership', M3, 'a', [contestId(mId(M2))]))), 'covers')
  assert.equal(w.admit(withContest, 'membership', signed('membership', M3, 'b')).ok, true, "b's own assertion is not shared")
})
