// F1–F5: the verifier composes the root record, a fresh head (R9) and the delegation, in F5's order.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const { verifier } = verifierModule
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
const CONFIG = Object.freeze({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400 })
const v = verifier(CONFIG)

const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)

function delegationText (over = {}, { secret, covers } = {}) {
  const body = { identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
    scopes: ['post', 'read'], nbf: NOW - 10, exp: NOW + 86_000, ...over }
  const { payload, id } = envelope.seal('delegation', body)
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  return { text: envelope.wrap(payload, { root: make({ covers: covers ?? [id], ...(secret ? { secret } : {}) }), subject }), id }
}

function headText (over = {}, { secret = W, witness = WITNESS, type = 'head' } = {}) {
  const body = { identity: IDENTITY, memberships: [IDENTITY], authority: [ROOT], at: NOW - 100, ...over }
  const { payload } = envelope.seal(type, body)
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)), witness })
}

const D = delegationText()
const call = (over = {}, ctx = {}) => {
  const r = v.verifyDelegation({ delegation: D.text, root: rootText, head: headText(), ...over }, { now: NOW, scope: 'post', revoked: [], ...ctx })
  return r.ok ? { ok: true } : { ...r }
}
const refused = (reason) => ({ ok: false, reason })

test('the base case is accepted, with the delegation id and body', () => {
  const r = v.verifyDelegation({ delegation: D.text, root: rootText, head: headText() }, { now: NOW, scope: 'post', revoked: [] })
  assert.equal(r.ok, true, JSON.stringify(r))
  assert.equal(r.id, D.id)
  assert.equal(r.body.root, ROOT)
  assert.ok(Object.isFrozen(r))
})

test('head: wrong type, wrong form, unpinned or out-of-window witness', () => {
  const cases = [
    ['an attestation, not a head', headText({}, { type: 'attestation' })],
    ['extra key', headText({ x: 1 })],
    ['no memberships', headText({ memberships: [] })],
    ['three memberships', headText({ memberships: [IDENTITY, '1'.repeat(64), '2'.repeat(64)] })],
    ['membership not an id', headText({ memberships: ['x'] })],
    ['the same membership twice', headText({ memberships: [IDENTITY, IDENTITY] })],
    ['six roots of authority', headText({ authority: ['1', '2', '3', '4', '5', '6'].map((c) => c.repeat(64)) })],
    ['no authority', headText({ authority: [] })],
    ['authority unsorted', headText({ authority: ['f'.repeat(64), ROOT] })],
    ['authority duplicated', headText({ authority: [ROOT, ROOT] })],
    ['at not an integer', headText({ at: String(NOW) })],
    ['identity not an id', headText({ identity: 'x' })],
    ['identity of 65 characters', headText({ identity: IDENTITY + '0' })],
    ['identity with a prefix', headText({ identity: 'x' + IDENTITY })],
    ['membership as an array', headText({ memberships: [[IDENTITY]] })],
    ['authority with a suffix', headText({ authority: [ROOT + '0'] })],
    ['unpinned witness', headText({}, { secret: APP, witness: hex(ed25519.getPublicKey(APP)) })],
    ['signed by another key than named', headText({}, { secret: APP })],
    ['not JSON', 'x'],
  ]
  for (const [name, head] of cases) assert.deepEqual(call({ head }), refused('head'), name)
  assert.deepEqual(call({ head: headText({ authority: [ROOT, 'f'.repeat(64)] }) }), { ok: true }, 'two roots of authority, sorted')
  assert.deepEqual(call({ head: headText({ at: 0 }) }), refused('stale'), 'at = 0 is a time, and long past')
  const edge = verifier({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: 0, exp: NOW - 100 }] })
  const e = edge.verifyDelegation({ delegation: D.text, root: rootText, head: headText() }, { now: NOW, scope: 'post', revoked: [] })
  assert.deepEqual({ ...e }, refused('head'), 'the key\'s window ends at the head\'s at')
  const window = verifier({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: NOW, exp: NOW + 10 }] })
  const r = window.verifyDelegation({ delegation: D.text, root: rootText, head: headText() }, { now: NOW, scope: 'post', revoked: [] })
  assert.deepEqual({ ...r }, refused('head'), 'the key\'s window does not hold the head\'s at')
})

test('stale: older than maxStaleness, or later than now plus skew', () => {
  assert.deepEqual(call({ head: headText({ at: NOW - 86_400 }) }), { ok: true }, 'exactly maxStaleness old')
  assert.deepEqual(call({ head: headText({ at: NOW - 86_401 }) }), refused('stale'))
  assert.deepEqual(call({ head: headText({ at: NOW + 60 }) }), { ok: true }, 'skew in the future')
  assert.deepEqual(call({ head: headText({ at: NOW + 61 }) }), refused('stale'))
})

test('root-record: any refusal of the root record; a root record of another key gives D7\'s root reason', () => {
  assert.deepEqual(call({ root: 'x' }), refused('root-record'))
  assert.deepEqual(call({ root: envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: 'other.example' }).payload) }), refused('root-record'))
  const other = '04' + hex(p256.getPublicKey(Uint8Array.from({ length: 32 }, (_, i) => i + 3), false).subarray(1))
  assert.deepEqual(call({ root: envelope.wrap(envelope.seal('root', { pub: other, rp_id: RP_ID }).payload) }), refused('root'))
})

test('the delegation\'s own reasons pass through', () => {
  assert.deepEqual(call({}, { now: NOW + 86_000 }), refused('expired'))
  assert.deepEqual(call({ delegation: delegationText({}, { covers: ['f'.repeat(64)] }).text }), refused('covers'))
  assert.deepEqual(call({ delegation: 'x' }), refused('envelope-encoding'))
})

test('identity, membership and authority are judged by the head', () => {
  assert.deepEqual(call({ head: headText({ identity: '9'.repeat(64) }) }), refused('identity'))
  assert.deepEqual(call({ head: headText({ memberships: ['5'.repeat(64)] }) }), refused('membership'))
  assert.deepEqual(call({ head: headText({ authority: ['0'.repeat(64)] }) }), refused('authority'))
  const pending = '6'.repeat(64)
  const underPending = delegationText({ membership: pending })
  assert.deepEqual(call({ delegation: underPending.text, head: headText({ memberships: [IDENTITY, pending] }) }), { ok: true }, 'under the pending successor')
  assert.deepEqual(call({ head: headText({ memberships: [IDENTITY, pending] }) }), { ok: true }, 'under the settled one, while pending')
})

test('revoked, audience and scope', () => {
  assert.deepEqual(call({}, { revoked: [D.id] }), refused('revoked'))
  assert.deepEqual(call({}, { revoked: ['f'.repeat(64), 1, null] }), { ok: true }, 'other entries do not matter')
  assert.deepEqual(call({ delegation: delegationText({ aud: 'https://other.example' }).text }), refused('audience'))
  assert.deepEqual(call({}, { scope: 'admin' }), refused('scope'))
  assert.deepEqual(call({}, { scope: 'read' }), { ok: true })
})

test('F3: adding revocations never turns a refusal into an accept', () => {
  const inputs = [D.id, 'f'.repeat(64), '0'.repeat(64)]
  fc.assert(fc.property(fc.subarray(inputs), fc.subarray(inputs), fc.constantFrom('post', 'read', 'admin'), (a, b, scope) => {
    const narrow = call({}, { revoked: a, scope })
    const wider = call({}, { revoked: [...a, ...b], scope })
    if (!narrow.ok) assert.equal(wider.ok, false)
  }), { seed: 20261103, numRuns: 100 })
})

test('programming errors: configuration, now, scope, revoked', () => {
  for (const c of [undefined, null, { ...CONFIG, audience: 'http://x' }, { ...CONFIG, maxStaleness: -1 }, { ...CONFIG, witnessKeys: null },
    { ...CONFIG, rpId: 1 }, { ...CONFIG, origin: undefined }, { ...CONFIG, skew: 1.5 }, { ...CONFIG, maxLifetime: '1' }]) {
    assert.throws(() => verifier(c), { name: 'TypeError', message: 'verifier configuration is not well formed' })
  }
  for (const ctx of [undefined, null, { now: -1, scope: 'post', revoked: [] }, { now: NOW, scope: 'Post', revoked: [] },
    { now: NOW, scope: 'post!', revoked: [] }, { now: NOW, scope: ['post'], revoked: [] },
    { now: NOW, scope: 'post', revoked: 'x' }, { now: NOW, scope: 'post' }]) {
    assert.throws(() => v.verifyDelegation({ delegation: D.text, root: rootText, head: headText() }, ctx),
      { name: 'TypeError', message: 'call must hold now, a scope and a revoked list' })
  }
})

test('the verifier is frozen; the configuration is copied at construction', () => {
  const config = { ...CONFIG, witnessKeys: [...CONFIG.witnessKeys] }
  const w = verifier(config)
  config.audience = 'https://evil.example'
  config.witnessKeys[0] = { key: '0'.repeat(64), nbf: 0, exp: 1 }
  assert.ok(Object.isFrozen(w))
  const r = w.verifyDelegation({ delegation: D.text, root: rootText, head: headText() }, { now: NOW, scope: 'post', revoked: [] })
  assert.equal(r.ok, true)
})

test('arbitrary records never throw', () => {
  for (const x of [undefined, null, 1, {}, [], 'x']) {
    for (const k of ['delegation', 'root', 'head']) {
      const r = v.verifyDelegation({ delegation: D.text, root: rootText, head: headText(), [k]: x }, { now: NOW, scope: 'post', revoked: [] })
      assert.ok(Object.isFrozen(r) && r.ok === false)
    }
  }
  assert.equal(v.verifyDelegation(undefined, { now: NOW, scope: 'post', revoked: [] }).ok, false)
  const hostile = new Proxy({}, { get () { throw new Error('trap') } })
  assert.deepEqual({ ...v.verifyDelegation(hostile, { now: NOW, scope: 'post', revoked: [] }) }, { ok: false, reason: 'head' })
})
