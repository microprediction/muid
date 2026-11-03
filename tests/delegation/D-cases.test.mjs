// D1–D7 on delegations built through the real envelope and a passkey-shaped assertion.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { build, result, rejects, consent, hex, BODY, CTX, NBF, SUBJECT, SUBJECT_SECRET, checkDelegation } from './helpers.mjs'
import { envelope } from '../impl.mjs'

const ok = build()

test('the base delegation is accepted', () => assert.deepEqual(result(ok), { ok: true }))

test('window (D1): nbf - skew - 1 not yet; nbf - skew and exp - 1 accepted; exp expired', () => {
  const at = (now) => result(ok, { ...CTX, now })
  assert.deepEqual(at(NBF - CTX.skew - 1), { ok: false, reason: 'not-yet' })
  assert.deepEqual(at(NBF - CTX.skew), { ok: true })
  assert.deepEqual(at(BODY.exp - 1), { ok: true })
  assert.deepEqual(at(BODY.exp), { ok: false, reason: 'expired' })
  assert.deepEqual(at(BODY.exp + CTX.skew - 1), { ok: false, reason: 'expired' }, 'skew never extends exp')
  assert.deepEqual(result(ok, { ...CTX, skew: 0, now: NBF - 1 }), { ok: false, reason: 'not-yet' })
  assert.deepEqual(result(ok, { ...CTX, skew: 0, now: NBF }), { ok: true })
})

test('lifetime (D2): at the cap accepted; one over, zero and negative refused', () => {
  const life = (exp) => build({ body: { ...BODY, exp } })
  assert.deepEqual(result(life(NBF + CTX.maxLifetime), { ...CTX }), { ok: true })
  rejects(life(NBF + CTX.maxLifetime + 1), 'lifetime', 'one over')
  rejects(life(NBF), 'lifetime', 'exp = nbf')
  rejects(life(NBF - 1), 'lifetime', 'exp < nbf')
})

test('shape: each key missing, an extra key, wrong forms', () => {
  for (const k of Object.keys(BODY)) {
    const { [k]: _, ...rest } = BODY
    rejects(build({ body: rest }), 'delegation-shape', `missing ${k}`)
  }
  rejects(build({ body: { ...BODY, extra: 1 } }), 'delegation-shape', 'extra key')
  const bad = {
    identity: ['1'.repeat(63), '1'.repeat(65), 'A'.repeat(64), 1],
    membership: ['g'.repeat(64), true],
    root: [['3'.repeat(64)], '3'.repeat(64).toUpperCase().replace(/3/g, 'F')],
    subject: [SUBJECT.toUpperCase(), SUBJECT.slice(2), 5],
    aud: [1, ['https://app.example']],
    scopes: ['read', { read: true }],
    // Floats and unsafe integers cannot be sealed at all (the encoder refuses them), so they are not listed.
    nbf: ['1800000000', -1, true],
    exp: ['1800086400', -1, true],
  }
  for (const [k, values] of Object.entries(bad)) {
    for (const v of values) rejects(build({ body: { ...BODY, [k]: v } }), 'delegation-shape', `${k} = ${JSON.stringify(v)}`)
  }
})

test('sig must be exactly { root, subject }, subject 128 lowercase hex', () => {
  const { payload, id } = envelope.seal('delegation', BODY)
  const root = JSON.parse(build()).sig.root
  for (const [name, sig] of [['no subject', { root }], ['extra', { root, subject: consent(id), x: 1 }],
    ['subject short', { root, subject: consent(id).slice(2) }], ['subject upper', { root, subject: consent(id).toUpperCase() }],
    ['subject number', { root, subject: 1 }], ['root missing', { subject: consent(id) }]]) {
    rejects(envelope.wrap(payload, sig), 'delegation-shape', name)
  }
})

test('scopes: 1–16 sorted distinct, each matching the grammar', () => {
  const s = (scopes) => build({ body: { ...BODY, scopes } })
  const sixteen = Array.from({ length: 16 }, (_, i) => 's' + String(i).padStart(2, '0'))
  assert.deepEqual(result(s(sixteen)), { ok: true })
  assert.deepEqual(result(s(['a', 'a.b', 'a:b', 'a_b', 'a-b', 'z' + 'x'.repeat(63)])), { ok: true })
  for (const [name, scopes] of [['empty', []], ['seventeen', [...sixteen, 'zz']], ['unsorted', ['read', 'post']],
    ['duplicate', ['read', 'read']], ['uppercase', ['Read']], ['too long', ['z' + 'x'.repeat(64)]], ['digit first', ['1a']],
    ['empty string', ['']], ['space', ['a b']], ['slash', ['a/b']], ['number', [1]]]) {
    rejects(s(scopes), 'scopes', name)
  }
})

test('aud (D5, O1): only a canonical origin', () => {
  for (const aud of ['http://app.example', 'https://app.example/', 'https://APP.example', 'https://app.example:443',
    'https://xn--app-kva.example', 'https://127.0.0.1', '']) {
    rejects(build({ body: { ...BODY, aud } }), 'aud', aud)
  }
  assert.deepEqual(result(build({ body: { ...BODY, aud: 'https://api.app.example:8443' } })), { ok: true })
})

test('subject key (K1): small-order and mixed-order keys are refused', () => {
  const small = 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'
  rejects(build({ body: { ...BODY, subject: small } }), 'subject-key', 'small order')
  const A = ed25519.Point.fromBytes(ed25519.getPublicKey(SUBJECT_SECRET))
  const mixed = hex(A.add(ed25519.Point.fromBytes(Buffer.from(small, 'hex'))).toBytes())
  rejects(build({ body: { ...BODY, subject: mixed } }), 'subject-key', 'mixed order')
})

test('root assertion: must cover this record and be signed by the root key', () => {
  rejects(build({ covers: ['f'.repeat(64)] }), 'covers', 'another record')
  rejects(build({ rootSecret: Uint8Array.from({ length: 32 }, (_, i) => i + 7) }), 'sig-invalid', 'another passkey')
  const { id } = envelope.seal('delegation', BODY)
  assert.deepEqual(result(build({ covers: ['0'.repeat(64), id, 'f'.repeat(64)].sort() })), { ok: true }, 'covered with others')
  rejects(ok, 'key-point', 'wrong root key in context', { ...CTX, rootKey: '04' + '00'.repeat(64) })
})

test('subject consent (D6): exactly the accept prefix and the raw id bytes, by the subject', () => {
  const { id } = envelope.seal('delegation', BODY)
  const other = envelope.seal('delegation', { ...BODY, exp: BODY.exp - 1 }).id
  for (const [name, subject] of [
    ['another key', consent(id, { secret: Uint8Array.from({ length: 32 }, (_, i) => i) })],
    ['hex text of the id', consent(id, { asHex: true })],
    ['signed-bytes prefix', consent(id, { prefix: 'muid/v1\n' })],
    ['assertion prefix', consent(id, { prefix: 'muid/v1/assert\n' })],
    ['no prefix', consent(id, { prefix: '' })],
    ['another delegation', consent(other)],
  ]) {
    rejects(build({ subject }), 'subject-consent', name)
  }
})

test('a context that is not well formed is a programming error', () => {
  for (const ctx of [undefined, null, { ...CTX, now: 1.5 }, { ...CTX, now: -1 }, { ...CTX, skew: '60' },
    { ...CTX, maxLifetime: 2 ** 53 }, { ...CTX, rootKey: 1 }, { ...CTX, rpId: undefined }, { ...CTX, origin: null }]) {
    assert.throws(() => checkDelegation(ok, ctx), TypeError, JSON.stringify(ctx))
  }
})

test('arbitrary texts and values never throw; envelope faults carry their V4 reason', () => {
  for (const r of [undefined, null, 1, 'x', [], {}, ok + ' ', ok.replace(String.raw`\"v\":1`, String.raw`\"v\":2`)]) {
    const out = checkDelegation(r, CTX)
    assert.ok(Object.isFrozen(out) && out.ok === false, JSON.stringify(r))
  }
  rejects('x', 'envelope-encoding', 'not JSON')
  const { payload } = envelope.seal('attestation', BODY)
  rejects(envelope.wrap(payload, { root: 1, subject: 2 }), 'type', 'another record type')
  rejects(envelope.wrap(envelope.seal('delegation', BODY).payload), 'envelope-shape', 'no sig')
})

test('the id checked is the id of the bytes given: a payload edited after signing fails the assertion', () => {
  const edited = ok.replace('\\"read\\"', '\\"reae\\"')
  assert.notEqual(edited, ok)
  rejects(edited, 'covers', 'a different payload is a different record')
})
