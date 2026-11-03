// R8 on hand-built record sets: what counts as a signature, a witness record, and an identity.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { membership, envelope } from '../impl.mjs'
import { history, witness } from '../../model/settled.mjs'
import { translate, identityFor, CTX_BASE, rootId, rootText, secretOf, WITNESS_KEYS } from './translate.mjs'
import { make } from '../assertion/helpers.mjs'

const { membershipState } = membership
const ctx = (genesis = 'a', extra = {}) => ({ ...CTX_BASE, identity: identityFor(genesis), ...extra })

test('the first root alone is epoch 1, settled, with authority', () => {
  const { records } = translate('a', [])
  const r = membershipState(records, ctx())
  assert.deepEqual(JSON.parse(JSON.stringify(r)), { ok: true, dead: false, membership: identityFor('a'), epoch: 1,
    roots: [rootId('a')], pending: false, authority: [rootId('a')], frozen: false })
  assert.ok(Object.isFrozen(r) && Object.isFrozen(r.roots) && Object.isFrozen(r.authority))
})

test('unknown-identity when no root given is the identity\'s first root', () => {
  const { records } = translate('a', [])
  assert.deepEqual({ ...membershipState({ ...records, roots: [] }, ctx()) }, { ok: false, reason: 'unknown-identity' })
  assert.deepEqual({ ...membershipState(records, ctx('b')) }, { ok: false, reason: 'unknown-identity' })
})

test('a settled change needs its anchor and settlement from a pinned witness key, in its window at their own time', () => {
  const items = history('a', [['a', 'b']])
  const { records } = translate('a', items)
  assert.equal(membershipState(records, ctx()).epoch, 2)
  assert.equal(membershipState({ ...records, settlements: [], anchors: [] }, ctx()).epoch, 1, 'no witness records: epoch 1')
  const late = [{ key: WITNESS_KEYS[0].key, nbf: 0, exp: 1_800_000_000 }]
  assert.equal(membershipState(records, ctx('a', { witnessKeys: late })).epoch, 1, 'witness key expired before the records')
  assert.equal(membershipState(records, ctx('a', { witnessKeys: [] })).epoch, 1, 'witness not pinned')
})

test('records that do not verify are ignored: an assertion over another record, or by a root not given', () => {
  const items = history('a', [['a', 'b']])
  const { records } = translate('a', items)
  assert.equal(membershipState(records, ctx()).epoch, 2, 'control')
  const reassert = (text, covers, letter) => {
    const e = JSON.parse(text)
    return envelope.wrap(e.payload, { root: e.sig.root, assertion: make({ covers, secret: secretOf(letter) }) })
  }
  const otherCover = records.memberships.map((t) => reassert(t, ['f'.repeat(64)], 'a'))
  assert.equal(membershipState({ ...records, memberships: otherCover }, ctx()).epoch, 1, 'assertions over another record')
  const wrongKey = records.memberships.map((t) => reassert(t, [JSON.parse(t).payload && envelope.seal('membership', JSON.parse(JSON.parse(t).payload).body).id], 'e'))
  assert.equal(membershipState({ ...records, memberships: wrongKey }, ctx()).epoch, 1, 'signed by a key that is not the named root')
  // Without b's root record, b's signature cannot count, and b is an added root (R1): epoch 2 is not valid.
  assert.equal(membershipState({ ...records, roots: [rootText('a')] }, ctx()).epoch, 1, 'a signer whose root record is missing')
})

test('arbitrary record values never throw; a malformed context is a programming error', () => {
  for (const records of [undefined, null, {}, { roots: 'x' }, { roots: [1, null, 'x'] }, { memberships: [{}] }]) {
    const r = membershipState(records, ctx())
    assert.ok(Object.isFrozen(r))
  }
  for (const c of [undefined, null, { ...ctx(), identity: 'x' }, { ...ctx(), witnessKeys: null }, { ...ctx(), rpId: 1 }]) {
    assert.throws(() => membershipState({}, c), { name: 'TypeError', message: 'context must hold identity, rpId, origin and witnessKeys' })
  }
})

test('witness() in the model and the translator agree on what gets anchored (sanity of the harness)', () => {
  const items = witness('a', history('a', [['a', 'b', 'c']]))
  const { records } = translate('a', items)
  assert.equal(records.anchors.length, items.filter((i) => i.kind === 'A').length)
  assert.equal(records.settlements.length, items.filter((i) => i.kind === 'S').length)
})
