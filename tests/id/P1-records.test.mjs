// The id page's records, in Node: what it builds verifies under the core, and what the core would refuse it refuses
// first, with a reason it can show.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { p256 } from '@noble/curves/nist.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { records } from './impl.mjs'
import * as wf from '../witness/fixtures.mjs'
import { root as rootModule, assertion as assertionModule, delegation as delegationModule, envelope } from '../impl.mjs'
import { challengeFor, authData, clientData, signOver, sha256 } from '../assertion/helpers.mjs'

const { rootRecord, challenge, assertion, delegation, handOff, b64u, fromB64u, MAX_LIFETIME, currentMembership, addRoot, rootSigned, changeToSign } = records
const hex = (b) => Buffer.from(b).toString('hex')
const RP_ID = 'localhost'
const ORIGIN = 'http://localhost:8080'
const SECRET = Uint8Array.from(sha256('id page test passkey'))
const POINT = p256.getPublicKey(SECRET, false)
const SPKI = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), POINT])
const WORKER = Uint8Array.from({ length: 32 }, (_, i) => 9 + i)
const SUBJECT = hex(ed25519.getPublicKey(WORKER))
const NOW = 1_800_000_000

test('the root record from a passkey: the core reads it, and its identity', () => {
  const r = rootRecord(SPKI.buffer.slice(SPKI.byteOffset, SPKI.byteOffset + SPKI.length), -7, RP_ID)
  const c = rootModule.checkRoot(r.text, { rpId: RP_ID })
  assert.equal(c.ok, true)
  assert.equal(r.id, c.id)
  assert.equal(c.key, hex(POINT))
  assert.equal(r.identity, rootModule.identityOf(c.id))
  assert.deepEqual(Object.keys(r), ['text', 'id', 'identity'])
})

test('only ES256 on P-256 is accepted (I6)', () => {
  assert.throws(() => rootRecord(SPKI, -8, RP_ID), { message: 'the passkey must use ES256 (P-256)' })
  assert.throws(() => rootRecord(SPKI, -257, RP_ID), { message: 'the passkey must use ES256 (P-256)' })
  for (const bad of [SPKI.subarray(1), Buffer.concat([SPKI, Buffer.from([0])]), Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030108034200', 'hex'), POINT])]) {
    assert.throws(() => rootRecord(bad, -7, RP_ID), { message: 'the passkey did not give a P-256 public key' })
  }
  const offCurve = Buffer.from(SPKI)
  offCurve[90] ^= 1
  assert.throws(() => rootRecord(offCurve, -7, RP_ID), { message: "the passkey's key is not usable: key-point" })
})

test('base64url without padding, both ways, for every length up to 40 and every byte value', () => {
  for (let n = 0; n <= 40; n++) {
    const b = Uint8Array.from({ length: n }, (_, i) => (i * 97 + n) & 0xff)
    assert.equal(b64u(b), Buffer.from(b).toString('base64url'))
    assert.deepEqual(fromB64u(b64u(b)), b)
  }
  const all = Uint8Array.from({ length: 256 }, (_, i) => i)
  assert.deepEqual(fromB64u(b64u(all)), all)
})

test('the challenge is W1, as the core computes it', () => {
  const covers = ['a'.repeat(64), 'b'.repeat(64)]
  assert.equal(Buffer.from(challenge(covers)).toString('base64url'), challengeFor(covers))
  assert.equal(Buffer.from(challenge(['c'.repeat(64)])).toString('base64url'), challengeFor(['c'.repeat(64)]))
})

test("the assertion object from the passkey's buffers verifies under the core", () => {
  const record = 'a'.repeat(64)
  const ad = authData({ rpId: RP_ID, flags: 0x05 })
  const cdj = Buffer.from(clientData({ challenge: challengeFor([record]), origin: ORIGIN }))
  const sig = signOver(ad, cdj, SECRET)
  const toBuf = (b) => Uint8Array.from(b).buffer
  const a = assertion([record], { authenticatorData: toBuf(ad), clientDataJSON: toBuf(cdj), signature: toBuf(sig) })
  assert.deepEqual(Object.keys(a), ['covers', 'authenticator_data', 'client_data_json', 'signature'])
  assert.equal(a.client_data_json, cdj.toString('base64url'))
  assert.equal(a.signature, sig.toString('base64url'))
  assert.deepEqual({ ...assertionModule.checkRootAssertion(a, { record, rpId: RP_ID, origin: ORIGIN, key: hex(POINT) }) }, { ok: true })
  // Every byte value encodes as base64url without padding.
  const all = Uint8Array.from({ length: 256 }, (_, i) => i)
  assert.equal(assertion([record], { authenticatorData: all.buffer, clientDataJSON: all.buffer, signature: all.buffer }).signature, Buffer.from(all).toString('base64url'))
})

test('a delegation to a worker: signed by the passkey and the worker, the core accepts it', () => {
  const r = rootRecord(SPKI, -7, RP_ID)
  const d = delegation({ identity: r.identity, membership: r.identity, root: r.id, subject: SUBJECT, aud: 'https://app.example',
    scopes: ['read', 'post', 'read'], now: NOW, lifetime: 86_400 })
  assert.deepEqual(d.body, { identity: r.identity, membership: r.identity, root: r.id, subject: SUBJECT, aud: 'https://app.example',
    scopes: ['post', 'read'], nbf: NOW, exp: NOW + 86_400 })
  assert.equal(d.id, envelope.seal('delegation', d.body).id)
  const ad = authData({ rpId: RP_ID, flags: 0x05 })
  const cdj = Buffer.from(clientData({ challenge: challengeFor([d.id]), origin: ORIGIN }))
  const rootSig = assertion([d.id], { authenticatorData: ad, clientDataJSON: cdj, signature: signOver(ad, cdj, SECRET) })
  const h = JSON.parse(handOff(d.payload, rootSig))
  assert.deepEqual(h, { payload: d.payload, root: rootSig })
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(d.id, 'hex')]), WORKER))
  const text = envelope.wrap(h.payload, { root: h.root, subject })
  const c = delegationModule.checkDelegation(text, { rootKey: hex(POINT), rpId: RP_ID, origin: ORIGIN, now: NOW + 10, skew: 60, maxLifetime: MAX_LIFETIME })
  assert.equal(c.ok, true, JSON.stringify(c))
})

test('what the core would refuse is refused first, with a reason to show', () => {
  const base = { identity: 'a'.repeat(64), membership: 'a'.repeat(64), root: 'b'.repeat(64), subject: SUBJECT, aud: 'https://app.example',
    scopes: ['post'], now: NOW, lifetime: 3600 }
  const refusals = [
    [{ subject: 'x' }, "the worker's key must be an Ed25519 public key, 64 hex digits"],
    [{ subject: SUBJECT.toUpperCase() }, "the worker's key must be an Ed25519 public key, 64 hex digits"],
    [{ subject: 'x' + SUBJECT.slice(1) }, "the worker's key must be an Ed25519 public key, 64 hex digits"],
    [{ subject: SUBJECT + '0' }, "the worker's key must be an Ed25519 public key, 64 hex digits"],
    [{ subject: 1 }, "the worker's key must be an Ed25519 public key, 64 hex digits"],
    [{ subject: '0'.repeat(63) + '2' }, "the worker's key must be an Ed25519 public key, 64 hex digits"],
    [{ aud: 'https://App.example' }, 'the audience must be an origin, such as https://app.example'],
    [{ aud: 'https://app.example/' }, 'the audience must be an origin, such as https://app.example'],
    [{ scopes: [] }, 'scopes must be 1 to 16 lower-case names'],
    [{ scopes: ['Post'] }, 'scopes must be 1 to 16 lower-case names'],
    [{ scopes: ['post', 1] }, 'scopes must be 1 to 16 lower-case names'],
    [{ scopes: [['post']] }, 'scopes must be 1 to 16 lower-case names'],
    [{ scopes: ['post!'] }, 'scopes must be 1 to 16 lower-case names'],
    [{ scopes: ['a'.repeat(65)] }, 'scopes must be 1 to 16 lower-case names'],
    [{ subject: 'x' + SUBJECT }, "the worker's key must be an Ed25519 public key, 64 hex digits"],
    [{ scopes: Array.from({ length: 17 }, (_, i) => `s${i}`) }, 'scopes must be 1 to 16 lower-case names'],
    [{ lifetime: 0 }, 'the lifetime must be 1 second to 7 days'],
    [{ lifetime: MAX_LIFETIME + 1 }, 'the lifetime must be 1 second to 7 days'],
    [{ lifetime: 1.5 }, 'the lifetime must be 1 second to 7 days'],
    // Found by review: SPEC §8 never grants attest this way.
    [{ scopes: ['post', 'attest'] }, 'the attest scope is not granted to a worker'],
  ]
  for (const [over, message] of refusals) assert.throws(() => delegation({ ...base, ...over }), { message }, JSON.stringify(over))
  for (const ok of [{ lifetime: 1 }, { lifetime: MAX_LIFETIME }, { scopes: Array.from({ length: 16 }, (_, i) => `s${String(i).padStart(2, '0')}`) }]) {
    assert.doesNotThrow(() => delegation({ ...base, ...ok }), JSON.stringify(ok).slice(0, 40))
  }
  assert.equal(MAX_LIFETIME, 604_800, 'decision 3: the id page gives machines at most 7 days')
})

// Adding a root (R1): the change is built against the membership the witness's records give, by the core's own
// membershipState; the page shows what it adds (I4).
import { ed25519 as ed } from '@noble/curves/ed25519.js'
const W_SECRET = Uint8Array.from({ length: 32 }, (_, i) => 120 + i)
const W_KEY = hex(ed.getPublicKey(W_SECRET))
const KEYS = [{ key: W_KEY, nbf: 0, exp: 4_000_000_000 }]
const OTHER = Uint8Array.from(sha256('id page test second passkey'))
const OTHER_SPKI = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), p256.getPublicKey(OTHER, false)])

test('the current membership, from what the witness holds', () => {
  const r = rootRecord(SPKI, -7, RP_ID)
  const records = { roots: [r.text], memberships: [], contests: [], freezes: [], anchors: [], settlements: [] }
  const s = currentMembership(records, { identity: r.identity, rpId: RP_ID, origin: ORIGIN, witnessKeys: KEYS })
  assert.deepEqual(s, { membership: r.identity, epoch: 1, roots: [r.id], authority: [r.id], pending: false })
  assert.throws(() => currentMembership({ roots: [] }, { identity: r.identity, rpId: RP_ID, origin: ORIGIN, witnessKeys: KEYS }),
    { message: 'the witness holds no record of this identity' })
  // A contested change ends the identity.
  const pending = wf.w.advance(wf.withM2(), wf.BASE).held
  const contested = wf.admitAll(pending, [['contest', wf.signed('contest', { identity: wf.IDENTITY, record: wf.mId(wf.M2) }, 'a')]])
  const dead = wf.w.advance(wf.w.advance(contested, wf.BASE + 1).held, wf.BASE + wf.WINDOW).held
  assert.throws(() => currentMembership(dead, wf.CTX), { message: 'this identity has ended' })
})

test('adding a root: the next epoch, its roots sorted, and what it adds; refusals with a reason', () => {
  const a = rootRecord(SPKI, -7, RP_ID)
  const b = rootRecord(OTHER_SPKI, -7, RP_ID)
  const state = { membership: a.identity, epoch: 1, roots: [a.id], authority: [a.id], pending: false }
  const c = addRoot({ identity: a.identity, state, root: b.text, rpId: RP_ID })
  assert.deepEqual(c.body, { identity: a.identity, prev: a.identity, epoch: 2, roots: [a.id, b.id].sort() })
  assert.equal(c.id, envelope.seal('membership', c.body).id)
  assert.equal(c.added, b.id)
  assert.throws(() => addRoot({ identity: a.identity, state, root: a.text, rpId: RP_ID }), { message: 'that passkey is already a root of this identity' })
  assert.throws(() => addRoot({ identity: a.identity, state, root: 'x', rpId: RP_ID }), { message: 'that is not a root record: envelope-encoding' })
  assert.throws(() => addRoot({ identity: a.identity, state: { ...state, pending: true }, root: b.text, rpId: RP_ID }),
    { message: 'a change is already pending: wait for it to settle' })
  const five = { ...state, roots: ['1', '2', '3', '4', '5'].map((x) => x.repeat(64)) }
  assert.throws(() => addRoot({ identity: a.identity, state: five, root: b.text, rpId: RP_ID }), { message: 'an identity has at most 5 roots' })
  assert.doesNotThrow(() => addRoot({ identity: a.identity, state: { ...state, roots: five.roots.slice(1) }, root: b.text, rpId: RP_ID }))
  // The new root sorts wherever its id falls: here before the existing one.
  const later = { ...state, roots: ['f'.repeat(64)] }
  assert.deepEqual(addRoot({ identity: a.identity, state: later, root: b.text, rpId: RP_ID }).body.roots, [b.id, 'f'.repeat(64)])
})

test('a root-signed record: the root and its assertion, as membership records carry them', () => {
  const a = rootRecord(SPKI, -7, RP_ID)
  const { payload, id } = envelope.seal('membership', { identity: a.identity, prev: a.identity, epoch: 2, roots: [a.id] })
  const sig = { covers: [id], authenticator_data: 'x', client_data_json: 'y', signature: 'z' }
  assert.deepEqual(JSON.parse(rootSigned(payload, a.id, sig)), { payload, sig: { root: a.id, assertion: sig } })
})

test('reading a change to co-sign: its body and id, or a reason', () => {
  const a = rootRecord(SPKI, -7, RP_ID)
  const body = { identity: a.identity, prev: a.identity, epoch: 2, roots: [a.id] }
  const { payload, id } = envelope.seal('membership', body)
  assert.deepEqual(changeToSign(payload), { body, id, payload })
  for (const bad of ['x', envelope.seal('freeze', { identity: a.identity, membership: a.identity }).payload, envelope.seal('membership', { ...body, roots: 'x' }).payload]) {
    assert.throws(() => changeToSign(bad), { message: 'that is not a membership change' })
  }
})
