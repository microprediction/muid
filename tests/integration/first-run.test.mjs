// The first-run flow, end to end: a passkey makes a root, the passkey delegates to an app's key, the witness computes
// the identity's state and signs a head (R9), and the relying party's verifier accepts the delegation (F5).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, root, membership, verifier as verifierModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_000
const APP = Uint8Array.from({ length: 32 }, (_, i) => 33 + i)
const WITNESS = Uint8Array.from({ length: 32 }, (_, i) => 99 + i)
const witnessKeys = [{ key: hex(ed25519.getPublicKey(WITNESS)), nbf: 0, exp: NOW + 10_000_000 }]
const AUD = 'https://app.example'

test('a first-time user: one root, one delegation, a head, accepted by the relying party', () => {
  // 1. The passkey's public key becomes an unsigned root record; its id and the identity id follow from it.
  const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
  const r = root.checkRoot(rootText, { rpId: RP_ID })
  const identity = root.identityOf(r.id)

  // 2. The id page builds the delegation; the passkey signs its id (one prompt) and the app key countersigns.
  const body = { identity, membership: identity, root: r.id, subject: hex(ed25519.getPublicKey(APP)), aud: AUD,
    scopes: ['post'], nbf: NOW, exp: NOW + 86_400 }
  const { payload, id } = envelope.seal('delegation', body)
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  const delegation = envelope.wrap(payload, { root: make({ covers: [id] }), subject })

  // 3. The witness computes the identity's state from the records it holds and signs a head.
  const state = membership.membershipState({ roots: [rootText] }, { identity, rpId: RP_ID, origin: ORIGIN, witnessKeys })
  const h = envelope.seal('head', membership.headOf(state, NOW))
  const head = envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), WITNESS)), witness: witnessKeys[0].key })

  // 4. The relying party verifies.
  const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys, skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
  const result = v.verifyDelegation({ delegation, root: rootText, head }, { now: NOW + 5, scope: 'post', revoked: [] })
  assert.equal(result.ok, true, JSON.stringify(result))
  assert.equal(result.id, id)
  assert.deepEqual({ ...v.verifyDelegation({ delegation, root: rootText, head }, { now: NOW + 86_401, scope: 'post', revoked: [] }) },
    { ok: false, reason: 'stale' }, 'a day later the head is stale (checked before the delegation, F5)')
})
