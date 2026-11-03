// A1, A3, A4: attestations built with the real seal and wrap and signed by a test witness key.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { attestation, envelope } from '../impl.mjs'

const { checkAttestation } = attestation
const hex = (b) => Buffer.from(b).toString('hex')
const W1 = Uint8Array.from({ length: 32 }, (_, i) => 50 + i)
const W2 = Uint8Array.from({ length: 32 }, (_, i) => 90 + i)
const K1 = hex(ed25519.getPublicKey(W1))
const K2 = hex(ed25519.getPublicKey(W2))
const NOW = 1_800_000_100
const KEYS = Object.freeze([{ key: K1, nbf: 1_700_000_000, exp: 1_900_000_000 }, { key: K2, nbf: 1_850_000_000, exp: 1_950_000_000 }])
const CTX = Object.freeze({ witnessKeys: KEYS, now: NOW, skew: 60, maxLifetime: 31_536_000 })
const BODY = Object.freeze({ root: '4'.repeat(64), provider: 'github', account: '583231', nbf: 1_800_000_000, exp: 1_800_086_400 })
const REASONS = ['envelope-encoding', 'envelope-shape', 'payload-size', 'payload-encoding', 'payload-shape', 'version', 'type',
  'attestation-shape', 'provider', 'account', 'lifetime', 'not-yet', 'expired', 'witness', 'key-encoding', 'key-point',
  'key-small-order', 'key-mixed-order', 'sig-encoding', 'sig-r-point', 'sig-r-small-order', 'sig-r-mixed-order', 'sig-s-range', 'sig-invalid']

function make ({ body = BODY, secret = W1, witness = K1, sig } = {}) {
  const { payload } = envelope.seal('attestation', body)
  const signature = hex(ed25519.sign(envelope.signedBytes(payload), secret))
  return envelope.wrap(payload, sig ?? { signature, witness })
}
const result = (t, ctx = CTX) => { const r = checkAttestation(t, ctx); return r.ok ? { ok: true } : { ...r } }
function rejects (t, reason, label, ctx = CTX) {
  assert.ok(REASONS.includes(reason), `${label}: test bug`)
  assert.deepEqual(result(t, ctx), { ok: false, reason }, label)
}
const ok = make()

test('the base attestation is accepted, carrying its id and body', () => {
  const r = checkAttestation(ok, CTX)
  assert.equal(r.ok, true)
  assert.equal(r.id, envelope.seal('attestation', BODY).id)
  assert.deepEqual(JSON.parse(JSON.stringify(r.body)), BODY)
  assert.ok(Object.isFrozen(r))
})

test('GitHub accounts: decimal, no leading zero, at most 20 digits', () => {
  for (const account of ['1', '583231', '9'.repeat(20)]) assert.deepEqual(result(make({ body: { ...BODY, account } })), { ok: true }, account)
  for (const account of ['0', '01', '9'.repeat(21), '-1', 'octocat', '1.0', ' 1', '']) rejects(make({ body: { ...BODY, account } }), 'account', account)
})

test('Google accounts: 1–255 printable ASCII characters without spaces', () => {
  const g = (account) => make({ body: { ...BODY, provider: 'google', account } })
  for (const account of ['110169484474386276334', '!'.repeat(255), 'aB-_.~']) assert.deepEqual(result(g(account)), { ok: true }, account)
  for (const account of ['', '!'.repeat(256), 'a b', 'café', 'a\tb', 'a\u007fb']) rejects(g(account), 'account', JSON.stringify(account))
})

test('ORCID accounts: dddd-dddd-dddd-dddX with the ISO 7064 MOD 11-2 check digit', () => {
  const o = (account) => make({ body: { ...BODY, provider: 'orcid', account } })
  // Example iDs published by ORCID.
  for (const account of ['0000-0002-1825-0097', '0000-0001-5109-3700', '0000-0002-1694-233X']) assert.deepEqual(result(o(account)), { ok: true }, account)
  for (const account of ['0000-0002-1825-0098', '0000-0001-5109-3701', '0000-0002-1694-2330', '0000-0002-1694-233x',
    '0000000218250097', 'https://orcid.org/0000-0002-1825-0097', '0000-0002-1825-009', '0000-0002-1825-00977', 'abcd-0002-1825-0097']) {
    rejects(o(account), 'account', account)
  }
})

test('provider: only github, google and orcid', () => {
  for (const provider of ['GitHub', 'linkedin', 'apple', '', 'github ']) rejects(make({ body: { ...BODY, provider } }), 'provider', provider)
})

test('shape: keys, field forms, sig form', () => {
  for (const k of Object.keys(BODY)) {
    const { [k]: _, ...rest } = BODY
    rejects(make({ body: rest }), 'attestation-shape', `missing ${k}`)
  }
  rejects(make({ body: { ...BODY, extra: 1 } }), 'attestation-shape', 'extra')
  for (const [k, v] of [['root', 'A'.repeat(64)], ['root', '4'.repeat(63)], ['provider', 1], ['account', 583231], ['nbf', -1], ['exp', '1']]) {
    rejects(make({ body: { ...BODY, [k]: v } }), 'attestation-shape', `${k} ${v}`)
  }
  const { payload } = envelope.seal('attestation', BODY)
  for (const sig of [{ signature: 'ab', witness: K1 }, { signature: '0'.repeat(128) }, { signature: '0'.repeat(128), witness: K1, x: 1 },
    { signature: '0'.repeat(128), witness: K1.toUpperCase() }, { signature: '0'.repeat(128).toUpperCase(), witness: K1 }]) {
    rejects(envelope.wrap(payload, sig), 'attestation-shape', JSON.stringify(sig).slice(0, 40))
  }
})

test('lifetime and window, as for delegations', () => {
  rejects(make({ body: { ...BODY, exp: BODY.nbf } }), 'lifetime', 'exp = nbf')
  rejects(make({ body: { ...BODY, exp: BODY.nbf + CTX.maxLifetime + 1 } }), 'lifetime', 'too long')
  assert.deepEqual(result(make({ body: { ...BODY, exp: BODY.nbf + CTX.maxLifetime } })), { ok: true })
  rejects(ok, 'not-yet', 'early', { ...CTX, now: BODY.nbf - CTX.skew - 1 })
  assert.deepEqual(result(ok, { ...CTX, now: BODY.nbf - CTX.skew }), { ok: true })
  rejects(ok, 'expired', 'at exp', { ...CTX, now: BODY.exp })
})

test('witness (A1): named, pinned, inside its own window', () => {
  const stranger = Uint8Array.from({ length: 32 }, (_, i) => 7 + i)
  rejects(make({ secret: stranger, witness: hex(ed25519.getPublicKey(stranger)) }), 'witness', 'not pinned')
  rejects(ok, 'witness', 'key not yet valid', { ...CTX, witnessKeys: [{ key: K1, nbf: NOW + 1, exp: NOW + 100 }] })
  rejects(ok, 'witness', 'key expired', { ...CTX, witnessKeys: [{ key: K1, nbf: 0, exp: NOW }] })
  assert.deepEqual(result(ok, { ...CTX, witnessKeys: [{ key: K1, nbf: NOW, exp: NOW + 1 }] }), { ok: true }, 'window edges')
  rejects(make({ secret: W2, witness: K1 }), 'sig-invalid', 'signed by another pinned key than the one named')
  rejects(make({ secret: W2, witness: K2 }), 'witness', 'the other key is outside its window now')
})

test('signature: over the signed bytes; any change is refused', () => {
  const { payload } = envelope.seal('attestation', BODY)
  const overPayload = hex(ed25519.sign(new TextEncoder().encode(payload), W1))
  rejects(envelope.wrap(payload, { signature: overPayload, witness: K1 }), 'sig-invalid', 'without the prefix')
  const good = JSON.parse(ok).sig.signature
  const flipped = good.slice(0, 127) + (good[127] === '0' ? '1' : '0')
  rejects(envelope.wrap(payload, { signature: flipped, witness: K1 }), 'sig-invalid', 'flipped')
})

test('context: well formed and read once; totality', () => {
  for (const ctx of [undefined, null, { ...CTX, now: -1 }, { ...CTX, skew: 1.5 }, { ...CTX, maxLifetime: '1' }, { ...CTX, witnessKeys: null },
    { ...CTX, witnessKeys: [{ key: 'ab', nbf: 0, exp: 1 }] }, { ...CTX, witnessKeys: [{ key: K1, nbf: 0 }] }]) {
    assert.throws(() => checkAttestation(ok, ctx), { name: 'TypeError', message: 'context must hold witnessKeys and non-negative now, skew, maxLifetime' })
  }
  let reads = 0
  const ctx = { ...CTX, get now () { return reads++ === 0 ? NOW : NaN } }
  assert.deepEqual(result(ok, ctx), { ok: true })
  assert.equal(reads, 1)
  for (const t of [undefined, 1, 'x', ok + ' ']) assert.equal(checkAttestation(t, CTX).ok, false)
  rejects(envelope.wrap(envelope.seal('delegation', BODY).payload, {}), 'type', 'a delegation')
})
