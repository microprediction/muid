// The first-run flow through every layer, composed the way SPEC §6's verifier obligations describe: a passkey makes a
// root, the identity follows from it, the passkey delegates to an app's key, and the verifier checks the delegation
// against the root record and the membership state. Not a substitute for the verifier; a record of the composition.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, root, delegation, membership } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_000
const APP = Uint8Array.from({ length: 32 }, (_, i) => 33 + i)

test('a first-time user: one root, one delegation, accepted end to end', () => {
  // 1. The passkey's public key becomes an unsigned root record; its id and the identity id follow from it.
  const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
  const r = root.checkRoot(rootText, { rpId: RP_ID })
  assert.equal(r.ok, true)
  const identity = root.identityOf(r.id)

  // 2. The id page builds the delegation, the passkey signs its id (one prompt), and the app key countersigns.
  const body = { identity, membership: identity, root: r.id, subject: hex(ed25519.getPublicKey(APP)), aud: 'https://app.example',
    scopes: ['post'], nbf: NOW, exp: NOW + 86_400 }
  const { payload, id } = envelope.seal('delegation', body)
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), APP))
  const text = envelope.wrap(payload, { root: make({ covers: [id] }), subject })

  // 3. The verifier: the root key from the root record the delegation names; then the delegation; then authority.
  const d = delegation.checkDelegation(text, { rootKey: r.key, rpId: RP_ID, origin: ORIGIN, now: NOW + 5, skew: 60, maxLifetime: 2_592_000 })
  assert.equal(d.ok, true, JSON.stringify(d))
  const state = membership.membershipState({ roots: [rootText] }, { identity, rpId: RP_ID, origin: ORIGIN, witnessKeys: [] })
  assert.equal(state.ok && !state.dead && !state.frozen, true)
  assert.equal(d.body.membership, state.membership, 'issued under the effective membership (epoch 1: the identity id)')
  assert.ok(state.authority.includes(d.body.root), 'its root has authority')
  assert.equal(d.body.aud, 'https://app.example', 'the relying party checks the audience is itself (D5)')
})
