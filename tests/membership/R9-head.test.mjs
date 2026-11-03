// R9: headOf turns a membership state into a head's body — settled then pending memberships, the authority, the time —
// and gives none for a dead or frozen identity.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { membership, envelope } from '../impl.mjs'
import { identityFor, CTX_BASE, rootId, rootText, rootSigned, witnessSigned, BASE } from './translate.mjs'

const { membershipState, headOf } = membership
const I = identityFor('a')
const ctx = { ...CTX_BASE, identity: I }
const ids = (...l) => l.map(rootId).sort()
const e2 = { identity: I, prev: I, epoch: 2, roots: ids('a', 'b') }
const id2 = envelope.seal('membership', e2).id
const roots = ['a', 'b', 'c'].map(rootText)
const sign = (body, ...letters) => letters.map((l) => rootSigned('membership', body, l))
const plain = (x) => JSON.parse(JSON.stringify(x))

test('epoch 1: one membership (the identity id), the first root', () => {
  const s = membershipState({ roots }, ctx)
  assert.deepEqual(plain(headOf(s, 77)), { identity: I, memberships: [I], authority: [rootId('a')], revoked: [], at: 77 })
})

test('pending: settled then pending, and only the shared roots', () => {
  const s = membershipState({ roots, memberships: sign(e2, 'a', 'b'), anchors: [witnessSigned('anchor', { identity: I, record: id2, at: BASE })] }, ctx)
  assert.equal(s.pending, true)
  assert.deepEqual(plain(headOf(s, 5)), { identity: I, memberships: [I, id2], authority: [rootId('a')], revoked: [], at: 5 })
})

test('settled: one membership and its roots', () => {
  const s = membershipState({ roots, memberships: sign(e2, 'a', 'b'), anchors: [witnessSigned('anchor', { identity: I, record: id2, at: BASE })],
    settlements: [witnessSigned('settlement', { identity: I, prev: I, outcome: id2, at: BASE + 1 })] }, ctx)
  assert.deepEqual(plain(headOf(s, 5)), { identity: I, memberships: [id2], authority: ids('a', 'b'), revoked: [], at: 5 })
})

test('no head for a dead or frozen identity, or for a refusal', () => {
  const frozen = membershipState({ roots, freezes: [rootSigned('freeze', { identity: I, membership: I }, 'a')] }, ctx)
  assert.equal(frozen.frozen, true)
  assert.equal(headOf(frozen, 1), undefined)
  assert.equal(headOf({ ok: true, dead: true }, 1), undefined)
  assert.equal(headOf({ ok: false, reason: 'records' }, 1), undefined)
  assert.equal(headOf(membershipState({ roots }, ctx), -1), undefined, 'a time is a non-negative integer')
  assert.equal(headOf(membershipState({ roots }, ctx), 0).at, 0, 'zero is a time')
  assert.deepEqual(plain(headOf(membershipState({ roots }, ctx), 3, ['f'.repeat(64), '0'.repeat(64)])).revoked, ['0'.repeat(64), 'f'.repeat(64)], 'revocations sorted')
  const s1 = membershipState({ roots }, ctx)
  assert.deepEqual(plain(headOf(s1, 3, ['f'.repeat(64), 'f'.repeat(64)])).revoked, ['f'.repeat(64)], 'duplicates once')
  assert.equal(headOf(s1, 3, ['x']), undefined, 'a revocation that is not an id')
  assert.equal(headOf(s1, 3, 'x'), undefined, 'revoked not a list')
  assert.equal(headOf(s1, 3, Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(64, '0'))), undefined, 'more than 64')
  assert.equal(headOf(s1, 3, Array.from({ length: 64 }, (_, i) => i.toString(16).padStart(64, '0'))).revoked.length, 64, '64 fit')
  const original = Array.prototype.sort
  Array.prototype.sort = function () { return this }
  let patched
  try { patched = plain(headOf(s1, 3, ['f'.repeat(64), '0'.repeat(64)])) } finally { Array.prototype.sort = original }
  assert.deepEqual(patched.revoked, ['0'.repeat(64), 'f'.repeat(64)], 'sorting does not use a patchable built-in')
  assert.equal(headOf({ ok: true, dead: false, frozen: false, pending: true, identity: I, settled: I, membership: 'x', authority: [] }, 1), undefined,
    'no head when no root has authority')
})
