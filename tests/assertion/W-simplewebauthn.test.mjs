// SPEC §12 differential: a root assertion this verifier accepts is also accepted by SimpleWebAuthn, a widely used
// WebAuthn server library, given the same key, challenge, origin and rp ID. One-directional: this verifier is
// stricter by design (W0–W5), and every case where only SimpleWebAuthn accepts is pinned below as a known difference,
// so a change in either direction is noticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { p256 } from '@noble/curves/nist.js'
import { verifyAuthenticationResponse } from '@simplewebauthn/server'
import fc from 'fast-check'
import { make, authData, clientData, challengeFor, result, b64u, KEY, ORIGIN, RP_ID, RECORD, SECRET } from './helpers.mjs'
import { runs } from '../runs.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = runs(300)

// The key as COSE (RFC 9053 EC2, ES256, P-256): {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
const point = Buffer.from(KEY, 'hex')
const COSE = new Uint8Array(Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
  point.subarray(1, 33), Buffer.from([0x22, 0x58, 0x20]), point.subarray(33)]))

async function theirs (sig) {
  try {
    const r = await verifyAuthenticationResponse({
      response: {
        id: 'AQ',
        rawId: 'AQ',
        type: 'public-key',
        clientExtensionResults: {},
        response: { clientDataJSON: sig.client_data_json, authenticatorData: sig.authenticator_data, signature: sig.signature },
      },
      expectedChallenge: challengeFor(sig.covers),
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: { id: 'AQ', publicKey: COSE, counter: 0 },
      requireUserVerification: true,
    })
    return r.verified === true
  } catch {
    return false
  }
}
const ours = (sig) => result(sig).ok === true

const CH = challengeFor([RECORD])
const highS = (() => {
  const base = make()
  const s = p256.Signature.fromBytes(Buffer.from(base.signature, 'base64url'), 'der')
  const flipped = new p256.Signature(s.r, p256.Point.CURVE().n - s.s)
  return { ...base, signature: b64u(flipped.toBytes('der')) }
})()

// [name, assertion, the known difference it shows, if only SimpleWebAuthn accepts it]
const CASES = [
  ['valid', make()],
  ['high S', highS],
  ['signature counter 1', make({ ad: authData({ count: 1 }) })],
  ['signature counter 2^32 - 1', make({ ad: authData({ count: 2 ** 32 - 1 }) })],
  ['another rp ID', make({ ad: authData({ rpId: 'other.example' }) })],
  ['trailing authenticator data byte', make({ ad: authData({ extra: new Uint8Array([0]) }) })],
  ['another key', make({ secret: Uint8Array.from(SECRET, (b) => b ^ 1) })],
  ['another record covered', make({ covers: ['b'.repeat(64)] }), 'W0: the record checked is among those covered'],
  ['type webauthn.create', make({ cdj: clientData({ challenge: CH, type: 'webauthn.create' }) })],
  ['another origin', make({ cdj: clientData({ challenge: CH, origin: 'https://other.example' }) })],
  ['another challenge', make({ cdj: clientData({ challenge: challengeFor(['b'.repeat(64)]) }) })],
  ['an extra client data key', make({ cdj: clientData({ challenge: CH, tail: ',"other_keys_can_be_added_here":"x"' }) })],
  ['topOrigin', make({ cdj: clientData({ challenge: CH, tail: ',"topOrigin":"https://other.example"' }) })],
  ['a second origin', make({ cdj: clientData({ challenge: CH, tail: ',"origin":"https://other.example"' }) })],
  ['a second type', make({ cdj: clientData({ challenge: CH, tail: ',"type":"webauthn.create"' }) })],
  ['crossOrigin true', make({ cdj: clientData({ challenge: CH, crossOrigin: 'true' }) }), 'W1 requires crossOrigin false'],
  ['no crossOrigin', make({ cdj: `{"type":"webauthn.get","challenge":"${CH}","origin":"${ORIGIN}"}` }), 'W1 prefix'],
  ['client data keys reordered', make({ cdj: `{"challenge":"${CH}","type":"webauthn.get","origin":"${ORIGIN}","crossOrigin":false}` }), 'W1 prefix'],
  ['token binding present', make({ cdj: clientData({ challenge: CH, tail: ',"tokenBinding":{"status":"present","id":"AQ"}' }) }), 'W1 refuses token binding'],
]

test('differential: every hand case agrees, or differs as pinned', async () => {
  for (const [name, sig, known] of CASES) {
    const [a, b] = [ours(sig), await theirs(sig)]
    if (known) assert.deepEqual([a, b], [false, true], `${name}: pinned as a known difference (${known})`)
    else assert.equal(a, b, `${name}: ours ${a}, SimpleWebAuthn ${b}`)
  }
  assert.equal(ours(make()), true, 'anti-vacuity: the valid case is accepted')
})

test('differential: every flags byte; ours is stricter only where a reserved bit is set (W2)', async () => {
  let both = 0
  const stricter = []
  for (let flags = 0; flags < 256; flags++) {
    const sig = make({ ad: authData({ flags }) })
    const [a, b] = [ours(sig), await theirs(sig)]
    assert.ok(!(a && !b), `flags 0x${flags.toString(16)}: accepted here, refused by SimpleWebAuthn`)
    if (a && b) both++
    if (!a && b) stricter.push(flags)
  }
  assert.ok(both >= 2, `flag bytes both accept: ${both}`)
  assert.deepEqual(stricter, [0x07, 0x0f, 0x1f, 0x25, 0x27, 0x2d, 0x2f, 0x3d, 0x3f])
  for (const f of stricter) assert.ok(f & 0x22, `0x${f.toString(16)} has a reserved bit set`)
})

test('differential: one changed byte in any field is never accepted here and refused there', async () => {
  const base = make()
  const fields = ['authenticator_data', 'client_data_json', 'signature']
  let refusedHere = 0
  await fc.assert(fc.asyncProperty(fc.constantFrom(...fields), fc.nat(), fc.integer({ min: 1, max: 255 }), async (field, at, xor) => {
    const bytes = Buffer.from(base[field], 'base64url')
    bytes[at % bytes.length] ^= xor
    const sig = { ...base, [field]: b64u(bytes) }
    const [a, b] = [ours(sig), await theirs(sig)]
    if (!a) refusedHere++
    assert.ok(!(a && !b), `${field} byte ${at % bytes.length} ^ ${xor}: accepted here, refused by SimpleWebAuthn`)
  }), { numRuns: RUNS, seed: SEED })
  assert.ok(refusedHere > RUNS / 2, `refused here: ${refusedHere} of ${RUNS}`)
})
