// Tamper sweep: every one-character change to any record a claim rests on (the claim, its delegation, the root record
// and the head) is refused. Each position is replaced by two other characters and deleted; none may verify.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 7 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 77 + i)
const AUD = 'https://app.example'
const REQUEST = 'POST https://app.example/posts sha256:0f00'
const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD,
  witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }], skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400,
  maxClaimAge: 300 })

const root = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(root, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const del = envelope.seal('delegation', { identity: IDENTITY, membership: IDENTITY, root: ROOT,
  subject: hex(ed25519.getPublicKey(APP)), aud: AUD, scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000 })
const delegation = envelope.wrap(del.payload, { root: make({ covers: [del.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })
const h = envelope.seal('head', { identity: IDENTITY, memberships: [IDENTITY], authority: [ROOT], revoked: [], at: NOW - 100 })
const head = envelope.wrap(h.payload, { signature: hex(ed25519.sign(envelope.signedBytes(h.payload), W)), witness: WITNESS })
const c = envelope.seal('claim', { delegation: del.id, scope: 'post', request: REQUEST, at: NOW - 5, data: { n: 1 } })
const claim = envelope.wrap(c.payload, { signature: hex(ed25519.sign(envelope.signedBytes(c.payload), APP)) })

const RECORDS = Object.freeze({ claim, delegation, root, head })
const CALL = Object.freeze({ now: NOW, scope: 'post', request: REQUEST, revoked: [] })

// Two replacements that differ from the original and from each other, so each position meets a character of another
// class as well as one of a nearby class: a hex digit becomes another hex digit, and so on.
function replacements (ch) {
  const near = String.fromCharCode(ch.charCodeAt(0) ^ 1)
  const far = ch === '0' ? '1' : '0'
  return near === far ? [near, 'x'] : [near, far]
}

function variants (text) {
  const out = []
  for (let i = 0; i < text.length; i++) {
    for (const r of replacements(text[i])) out.push(text.slice(0, i) + r + text.slice(i + 1))
    out.push(text.slice(0, i) + text.slice(i + 1))
  }
  return out
}

test('the untampered records verify', () => {
  assert.equal(v.verifyClaim(RECORDS, CALL).ok, true)
  assert.equal(v.verifyDelegation(RECORDS, CALL).ok, true)
})

for (const name of ['claim', 'delegation', 'root', 'head']) {
  test(`every one-character change to the ${name} is refused`, () => {
    const all = variants(RECORDS[name])
    let accepted = 0
    const first = []
    for (const t of all) {
      const r = v.verifyClaim({ ...RECORDS, [name]: t }, CALL)
      if (r.ok) {
        accepted++
        if (first.length < 3) first.push(t)
      }
    }
    assert.equal(accepted, 0, `${accepted} of ${all.length} verified, e.g. ${first.join('\n')}`)
    assert.ok(all.length > 3 * 100, 'the sweep covers the whole record')
  })
}
