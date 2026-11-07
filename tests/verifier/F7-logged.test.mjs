// R10 and F5's `logged`: a delegation verifies only with the witness's logged record naming it, as a browser accepts
// a certificate only with a log's signed timestamp. Checked after `revoked` and before `audience`.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const { verifier } = verifierModule
const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const OTHER = Uint8Array.from({ length: 32 }, (_, i) => 30 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
// The witness key's window opened at NOW - 500.
const CONFIG = Object.freeze({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: NOW - 500, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
const v = verifier(CONFIG)

const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)

function delegation (over = {}) {
  const body = { identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
    scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000, ...over }
  const { payload, id } = envelope.seal('delegation', body)
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  return { text: envelope.wrap(payload, { root: make({ covers: [id] }), subject }), id }
}
const D = delegation()

function signedBy (type, body, secret = W) {
  const { payload } = envelope.seal(type, body)
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)), witness: hex(ed25519.getPublicKey(secret)) })
}
const logged = (over = {}, secret, type = 'logged') => signedBy(type, { identity: IDENTITY, delegation: D.id, at: NOW - 5, ...over }, secret)
const head = (revoked = []) => signedBy('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked, at: NOW - 100 })

const verify = (records, call = {}) => {
  const r = v.verifyDelegation({ delegation: D.text, root: rootText, head: head(), logged: logged(), ...records }, { now: NOW, scope: 'post', revoked: [], ...call })
  return r.ok ? { ok: true } : { ...r }
}
const refused = (reason) => ({ ok: false, reason })

test('with the logged record naming it, the delegation is accepted', () => {
  assert.deepEqual(verify({}), { ok: true })
})

test('logged: missing, or not the witness\'s logged record of this identity and this delegation', () => {
  const cases = [
    ['missing', undefined],
    ['not a text', 7],
    ['not an envelope', 'logged'],
    ['a head, not a logged record', logged({}, W, 'head')],
    ['another delegation', logged({ delegation: delegation({ scopes: ['read'] }).id })],
    ['another identity', logged({ identity: 'f'.repeat(64) })],
    ['an extra key', logged({ x: 1 })],
    ['no time', signedBy('logged', { identity: IDENTITY, delegation: D.id })],
    ['a time that is not a number', logged({ at: '1' })],
    ['an unpinned key', logged({}, OTHER)],
  ]
  for (const [name, text] of cases) assert.deepEqual(verify({ logged: text }), refused('logged'), name)
  // A forged signature: the witness's key named, another key's signature.
  const { payload } = envelope.seal('logged', { identity: IDENTITY, delegation: D.id, at: NOW - 5 })
  const forged = envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), OTHER)), witness: WITNESS })
  assert.deepEqual(verify({ logged: forged }), refused('logged'), 'forged')
  // At the key's window's edges, under a delegation whose own window holds them: its first second counts, the one
  // before does not, and its end is not in it.
  const early = delegation({ nbf: NOW - 600 })
  const logEarly = (at) => signedBy('logged', { identity: IDENTITY, delegation: early.id, at })
  assert.deepEqual(verify({ delegation: early.text, logged: logEarly(NOW - 500) }), { ok: true }, 'the first second')
  assert.deepEqual(verify({ delegation: early.text, logged: logEarly(NOW - 501) }), refused('logged'), 'before the key\'s window')
  const closing = verifier({ ...CONFIG, witnessKeys: [{ key: WITNESS, nbf: NOW - 500, exp: NOW + 1 }] })
  const at = (t) => closing.verifyDelegation({ delegation: D.text, root: rootText, head: head(), logged: logged({ at: t }) }, { now: NOW, scope: 'post', revoked: [] }).ok
  assert.equal(at(NOW), true, 'the key\'s last second')
  assert.equal(at(NOW + 1), false, 'after the key\'s window')
})

test('order: after revoked, before audience', () => {
  assert.deepEqual(verify({ head: head([D.id]), logged: undefined }), refused('revoked'))
  const elsewhere = delegation({ aud: 'https://other.example' })
  assert.deepEqual(verify({ delegation: elsewhere.text, logged: undefined }), refused('logged'))
  assert.deepEqual(verify({ delegation: elsewhere.text, logged: logged({ delegation: elsewhere.id }) }), refused('audience'))
})

test('the logged record is read once from the records', () => {
  let reads = 0
  const records = { delegation: D.text, root: rootText, head: head(), get logged () { reads++; return logged() } }
  assert.equal(v.verifyDelegation(records, { now: NOW, scope: 'post', revoked: [] }).ok, true)
  assert.equal(reads, 1)
})

// Found by fuzzing: a signed logged record whose `at` was not a time threw (its `at + 1` on a decoded object) where
// it should be refused. Its body is now checked for its form before its signature, as a head's is.
test('a logged record of the wrong form is refused, never thrown on, even when the witness signed it', () => {
  // Values the encoder accepts (it refuses floats and unsafe integers outright).
  for (const over of [{ at: [] }, { at: {} }, { at: [1] }, { at: '1' }, { at: true }, { at: -1 },
    { identity: [] }, { identity: 'x' }, { delegation: {} }, { delegation: D.id.toUpperCase() }]) {
    const text = logged(over)
    let r
    assert.doesNotThrow(() => { r = verify({ logged: text }) }, JSON.stringify(over))
    assert.deepEqual(r, refused('logged'), JSON.stringify(over))
  }
})

// Found by review: a head carries only revocations that name a live logged delegation, and revocations are kept for
// good; so a head that no longer names a revocation the relying party's last head carried does not revive it.
test('a revocation in the last head stays: a later head without it does not revive the delegation', () => {
  const at = (t, revoked = []) => signedBy('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked, at: t })
  for (const target of [D.id, hex(ed25519.getPublicKey(APP))]) {
    assert.deepEqual(verify({ head: at(NOW - 50) }, { lastHead: at(NOW - 60, [target]) }), refused('revoked'), target === D.id ? 'by id' : 'by subject key')
  }
  assert.deepEqual(verify({ head: at(NOW - 50) }, { lastHead: at(NOW - 60, ['e'.repeat(64)]) }), { ok: true }, 'another revoked')
})

// Found by review: a logged record was accepted at any time its witness key was valid, so a retired key could date
// one before a revocation. The witness logs only a delegation that verifies, so its record falls in the delegation's
// window: from nbf, less the skew, to exp.
test('a logged record outside its delegation\'s window is refused', () => {
  assert.deepEqual(verify({ logged: logged({ at: NOW - 10 - 60 }) }), { ok: true }, 'nbf, less the skew')
  assert.deepEqual(verify({ logged: logged({ at: NOW - 10 - 61 }) }), refused('logged'), 'a second before')
  const long = delegation({ exp: NOW + 10 })
  const logLong = (t) => signedBy('logged', { identity: IDENTITY, delegation: long.id, at: t })
  assert.deepEqual(verify({ delegation: long.text, logged: logLong(NOW + 9) }), { ok: true }, 'a second before exp')
  assert.deepEqual(verify({ delegation: long.text, logged: logLong(NOW + 10) }), refused('logged'), 'at exp')
})
