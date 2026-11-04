// W3C WebAuthn L3 §16 ES256 authentication examples (pinned excerpt): authenticator data and client data byte for
// byte except the challenge, which becomes a muid challenge; re-signed with the published credential private key.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { p256 } from '@noble/curves/nist.js'
import { result, challengeFor, signOver, b64u, hex, RECORD } from './helpers.mjs'

const text = readFileSync(new URL('../vectors/webauthn-l3/test-vectors.bs', import.meta.url), 'utf8')
const field = (name, src) => (new RegExp(`^${name} = h'([0-9a-f]+)'`, 'm').exec(src) ?? [])[1]

const examples = text.split(/\n## /).slice(1).map((section) => {
  const [registration, authentication] = section.split('authentication ceremony|Authentication')
  return {
    title: section.split(' ## ')[0],
    secret: field('credential_private_key', registration),
    authData: field('authenticatorData', authentication ?? ''),
    clientData: field('clientDataJSON', authentication ?? ''),
  }
}).filter((e) => e.secret?.length === 64 && e.authData)

// Expected outcome per example, from its documented construction (flags byte and client data).
const EXPECTED = {
  'ES256 Credential with No Attestation': 'user-verification', // flags 0x19: no UV
  'ES256 Credential with Self Attestation': 'user-verification', // 0x09
  'ES256 Credential with "crossOrigin": true in clientDataJSON': 'client-data',
  'ES256 Credential with "topOrigin" in clientDataJSON': 'client-data',
  'ES256 Credential with very long credential ID': 'ok', // 0x0d
  'Packed Attestation with ES256 Credential': 'ok', // 0x0d, extraData after the prefix
  'TPM Attestation with ES256 Credential': 'ok', // 0x0d
  'Android Key Attestation with ES256 Credential': 'user-verification', // 0x09
  'Apple Anonymous Attestation with ES256 Credential': 'user-verification', // 0x09
  'FIDO U2F Attestation with ES256 Credential': 'user-verification', // 0x01
}

test('the ten ES256 authentication examples are found', () => {
  assert.deepEqual(examples.map((e) => e.title).sort(), Object.keys(EXPECTED).sort())
})

for (const e of examples) {
  test(`${e.title}: ${EXPECTED[e.title]}`, () => {
    const original = Buffer.from(e.clientData, 'hex').toString('utf8')
    const covers = [RECORD]
    const json = original.replace(/"challenge":"[A-Za-z0-9_-]+"/, `"challenge":"${challengeFor(covers)}"`)
    assert.notEqual(json, original)
    const ad = Buffer.from(e.authData, 'hex')
    const sig = { covers, authenticator_data: b64u(ad), client_data_json: b64u(Buffer.from(json)), signature: b64u(signOver(ad, json, Buffer.from(e.secret, 'hex'))) }
    const key = '04' + hex(p256.getPublicKey(Buffer.from(e.secret, 'hex'), false).subarray(1))
    const r = result(sig, { record: RECORD, rpId: 'example.org', origin: 'https://example.org', key })
    assert.deepEqual(r, EXPECTED[e.title] === 'ok' ? { ok: true } : { ok: false, reason: EXPECTED[e.title] })
  })
}
