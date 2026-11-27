// muid/testing, used as a service's tests would use it: through the package's entries alone, against the real
// verifier, adapter and receipt check.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { testIdentity, testLog } from 'muid/testing'
import { verifier } from 'muid/verifier'
import { relyingParty } from 'muid/adapter'
import { memoryStore } from 'muid/adapter/stores'
import { verifyCheckpoint } from 'muid/checkpoint'
import { verifyReceipt } from 'muid/receipt'
import { verifyInclusion, leafHash } from 'muid/merkle'
import { seal, wrap, signedBytes, open } from 'muid/envelope'
import { newKey, enrol, request } from 'muid/worker'

const NOW = 1_800_000_000
const AUD = 'https://store.test'
const URL_ = AUD + '/blobs'
const clock = () => NOW
const hex = (b) => Buffer.from(b).toString('hex')
const service = (id, over = {}) => verifier({ ...id.verifier, audience: AUD, maxStaleness: 86_400, maxClaimAge: 300, ...over })
const call = (over = {}) => ({ now: NOW, scope: 'put', method: 'POST', url: URL_, revoked: [], ...over })

test('a request made by a test identity\'s agent is accepted by the real verifier, and once by the adapter', async () => {
  const id = testIdentity({ clock })
  const a = id.agent({ name: 'uploader', aud: AUD, scopes: ['put', 'get'] })
  const records = a.records({ url: URL_, data: { size: 3 } })
  assert.deepEqual(Object.keys(records).sort(), ['claim', 'delegation', 'head', 'logged', 'root'])
  const v = service(id)
  const r = v.verifyClaim(records, call())
  assert.equal(r.ok, true, JSON.stringify(r))
  assert.deepEqual([r.delegation.body.identity, r.delegation.body.agent, JSON.stringify(r.body.data)], [id.identity, 'uploader', '{"size":3}'])
  assert.equal(open(records.delegation, 'delegation').id, a.id)
  assert.equal(v.verifyHead(id.head(), call()).identity, id.identity)
  const rp = relyingParty({ verifier: v, store: memoryStore(), clock })
  let acted = 0
  const first = await rp.acceptClaim(records, call(), () => { acted++ })
  assert.equal(first.ok, true, JSON.stringify(first))
  const again = await rp.acceptClaim(records, call(), () => { acted++ })
  assert.deepEqual([again.ok, acted], [false, 1], 'a claim is used once')
  // What the service checks, it refuses when the request differs.
  assert.equal(v.verifyClaim(a.records({ url: URL_, scope: 'get' }), call({ scope: 'get' })).ok, true)
  assert.equal(v.verifyClaim(records, call({ scope: 'delete' })).ok, false)
  assert.equal(v.verifyClaim(records, call({ url: AUD + '/other' })).reason, 'claim-url')
  assert.equal(v.verifyClaim(records, call({ method: 'PUT' })).reason, 'claim-method')
  const bound = a.records({ url: URL_, nonce: 'n-1', contentDigest: Buffer.alloc(32).toString('base64') })
  assert.equal(v.verifyClaim(bound, call({ nonce: 'n-1', contentDigest: Buffer.alloc(32).toString('base64') })).ok, true)
  assert.equal(v.verifyClaim(bound, call()).reason, 'claim-nonce')
  // Another service's verifier refuses it: the delegation names this audience.
  assert.equal(verifier({ ...id.verifier, audience: 'https://other.test', maxStaleness: 86_400, maxClaimAge: 300 }).verifyClaim(records, call()).ok, false)
})

test('the cases a service should test: a revoked delegation, a stale head, an old claim, an expired delegation', () => {
  let now = NOW
  const id = testIdentity({ clock: () => now })
  const a = id.agent({ aud: AUD, scopes: ['put'] })
  const b = id.agent({ name: 'second', aud: AUD, scopes: ['put'] })
  const v = service(id)
  assert.equal(v.verifyClaim(a.records({ url: URL_ }), call()).ok, true)
  // A head signed long ago is refused; so is a claim signed long ago.
  assert.equal(v.verifyClaim(a.records({ url: URL_, headAt: NOW - 86_401 - 60 }), call()).ok, false)
  assert.equal(v.verifyClaim(a.records({ url: URL_, at: NOW - 301 - 60 }), call()).ok, false)
  // Revoked: heads from then on list it, and the other agent goes on working.
  a.revoke()
  const revoked = v.verifyClaim(a.records({ url: URL_ }), call())
  assert.equal(revoked.ok, false)
  assert.equal(v.verifyClaim(b.records({ url: URL_ }), call()).ok, true)
  // Past its lifetime, a delegation is refused.
  now = NOW + 3600 + 61
  assert.equal(v.verifyClaim(b.records({ url: URL_ }), call({ now })).ok, false)
})

test('a worker with its own key: the hand-off the page would give it, enrolled at the test witness, makes requests the adapter accepts', async () => {
  const id = testIdentity({ clock })
  const key = newKey()
  const handOff = id.handOff({ subject: key.subject, aud: AUD, scopes: ['put', 'get', 'put'], agent: 'drive', lifetime: 600 })
  assert.deepEqual(Object.keys(JSON.parse(handOff)), ['payload', 'root'])
  assert.equal(id.witness.url, 'https://id.test/witness/')
  const w = await enrol({ handOff, secret: key.secret, ...id.witness })
  assert.deepEqual([w.identity, w.agent, w.aud, w.scopes, w.nbf, w.exp, w.root], [id.identity, 'drive', AUD, ['get', 'put'], NOW, NOW + 600, id.rootText])
  const records = await request(w, key.secret, { scope: 'put', method: 'POST', url: URL_, data: { size: 3 }, at: NOW }, id.witness)
  const rp = relyingParty({ verifier: service(id), store: memoryStore(), clock })
  const first = await rp.acceptClaim(records, call(), (r) => r.delegation.body.identity)
  assert.equal(first.ok, true, JSON.stringify(first))
  assert.equal(first.value, id.identity)
  assert.equal((await rp.acceptClaim(records, call(), () => {})).reason, 'replay')
  // One witness, however it is reached: a head signed directly follows the service's, and an agent made directly is
  // among what the service holds; a revocation made directly is in the next head the service gives.
  assert.equal((await rp.acceptHead({ head: id.head() }, call())).ok, true)
  const a = id.agent({ name: 'uploader', aud: AUD, scopes: ['put'] })
  assert.equal((await rp.acceptClaim(a.records({ url: URL_ }), call(), () => {})).ok, true)
  a.revoke()
  const after = await request(w, key.secret, { scope: 'put', method: 'POST', url: URL_, at: NOW }, id.witness)
  assert.deepEqual(JSON.parse(JSON.stringify(open(after.head, 'head').body.revoked)), [a.id])
  assert.equal((await rp.acceptClaim(after, call(), () => {})).ok, true, 'the worker itself is not revoked')
  assert.equal((await rp.acceptClaim(a.records({ url: URL_, data: { n: 2 } }), call(), () => {})).reason, 'revoked')
  // Defaults: the agent is named worker, for an hour from now. The witness is at its own URL and nowhere else.
  const plain = await enrol({ handOff: id.handOff({ subject: key.subject, aud: AUD, scopes: ['put'] }), secret: key.secret, ...id.witness })
  assert.deepEqual([plain.agent, plain.nbf, plain.exp], ['worker', NOW, NOW + 3600])
  await assert.rejects(id.witness.fetch('https://elsewhere.test/witness/v1/records'), { name: 'TypeError', message: /^muid\/testing: the test witness is at https:\/\/id\.test\/witness\/, not / })
  // Another identity registers at the same service as it would at any witness, and neither sees the other's records.
  const other = testIdentity({ seed: 'another', clock })
  const post = await id.witness.fetch(id.witness.url + 'v1/records', { method: 'POST', body: JSON.stringify({ identity: other.identity, type: 'root', text: other.rootText }) })
  assert.equal((await post.json()).ok, true)
  const theirs = await (await id.witness.fetch(id.witness.url + `v1/identities/${other.identity}/records`)).json()
  assert.deepEqual(theirs.roots, [other.rootText])
  assert.deepEqual((await (await id.witness.fetch(id.witness.url + `v1/identities/${id.identity}/records`)).json()).roots, [id.rootText])
})

test('identities are named by their seed; a witness of one does not sign for another', () => {
  const one = testIdentity({ clock })
  const same = testIdentity({ clock })
  const other = testIdentity({ seed: 'another', clock })
  assert.equal(same.identity, one.identity)
  assert.notEqual(other.identity, one.identity)
  assert.equal(one.agent({ aud: AUD, scopes: ['put'] }).subject, same.agent({ aud: AUD, scopes: ['put'] }).subject)
  assert.notEqual(one.agent({ name: 'x', aud: AUD, scopes: ['put'] }).subject, one.agent({ name: 'y', aud: AUD, scopes: ['put'] }).subject)
  const records = other.agent({ aud: AUD, scopes: ['put'] }).records({ url: URL_ })
  assert.equal(service(one).verifyClaim(records, call()).ok, false, 'pinned to the first identity\'s witness')
  assert.equal(service(other).verifyClaim(records, call()).ok, true)
  assert.throws(() => one.agent({ aud: 'not an origin', scopes: ['put'] }), { message: /^muid\/testing: the test witness refused the delegation: / })
})

test('the test log: checkpoints the real check takes, proofs that hold, and a receipt bundle verifyReceipt accepts', async () => {
  const id = testIdentity({ clock })
  const a = id.agent({ aud: AUD, scopes: ['put'] })
  const records = a.records({ url: URL_ })
  const accepted = service(id).verifyClaim(records, call())
  // The service's receipt for the accepted claim, signed with its own key (issuing is the service's, not this entry's).
  const secret = Uint8Array.from({ length: 32 }, (_, i) => 9 + i)
  const key = hex(ed25519.getPublicKey(secret))
  const { payload } = seal('receipt', { service: AUD, identity: id.identity, delegation: a.id, claim: accepted.id, at: NOW })
  const receipt = wrap(payload, { signature: hex(ed25519.sign(signedBytes(payload), secret)), service: key })
  const log = testLog({ clock })
  for (const filler of ['a', 'b', 'c']) await log.append(filler)
  const index = await log.append(receipt)
  assert.equal(index, 3)
  await log.append('d')
  assert.deepEqual(log.entries(), ['a', 'b', 'c', receipt, 'd'])
  const text = await log.checkpoint()
  const c = verifyCheckpoint(text, { ...log.checkpoints, now: NOW, skew: 60 })
  assert.equal(c.ok, true, JSON.stringify(c))
  assert.equal(c.size, 5)
  for (let i = 0; i < 5; i++) {
    const proof = await log.inclusionProof(i, 5)
    assert.equal(verifyInclusion({ leafHash: leafHash(new TextEncoder().encode(log.entries()[i])), index: i, size: 5, proof, root: Buffer.from(c.root, typeof c.root === 'string' ? 'hex' : undefined) }), true, `entry ${i}`)
  }
  const proof = await log.inclusionProof(index, 5)
  const ctx = { services: [{ origin: AUD, key, nbf: 0, exp: 4_000_000_000 }], log: log.checkpoints, now: NOW, skew: 60 }
  const bundle = verifyReceipt({ receipt, checkpoint: text, proof, index, claim: records.claim }, ctx)
  assert.equal(bundle.ok, true, JSON.stringify(bundle))
  assert.equal(verifyReceipt({ receipt, checkpoint: text, proof, index: 2 }, ctx).ok, false)
  // A checkpoint from another log's keys is not this log's.
  assert.equal(verifyCheckpoint(await testLog({ seed: 'another', clock }).checkpoint(), { ...log.checkpoints, now: NOW, skew: 60 }).ok, false)
  for (const [i, size] of [[5, 5], [0, 6], [-1, 5], [0, 0], [1.5, 5]]) await assert.rejects(log.inclusionProof(i, size), RangeError)
  const empty = testLog({ clock })
  assert.equal(verifyCheckpoint(await empty.checkpoint(), { ...empty.checkpoints, now: NOW, skew: 60 }).size, 0)
})

test('the entry is built through the package\'s other entries and its two crypto libraries, and nothing else', () => {
  const source = readFileSync(new URL('../../testing/index.js', import.meta.url), 'utf8')
  const imports = [...source.matchAll(/from '([^']+)'/g)].map((m) => m[1])
  assert.ok(imports.length > 0)
  for (const from of imports) assert.match(from, /^(muid\/(envelope|root|witness|witness\/service|merkle)|@noble\/(curves|hashes)\/[a-z0-9]+\.js)$/, from)
  assert.equal(/\bimport\(|require\(/.test(source), false)
})

// SPEC C1, after the fact: a claim accepted with its records kept is checked again, long after its delegation lapsed,
// as of its own time; at any later time it is refused, and records gathered later are not the ones it was made with.
test('a claim kept with its records verifies again as of its own time, after its delegation has lapsed', () => {
  let now = NOW
  const id = testIdentity({ clock: () => now })
  const a = id.agent({ aud: AUD, scopes: ['put'], lifetime: 3600 })
  const digest = Buffer.alloc(32, 7).toString('base64')
  const kept = a.records({ url: URL_, contentDigest: digest })
  const v = service(id)
  assert.equal(v.verifyClaim(kept, call({ contentDigest: digest })).ok, true, 'accepted when it was made')
  now += 90 * 86_400
  const at = open(kept.claim, 'claim').body.at
  const again = v.verifyClaim(kept, call({ now: at, contentDigest: digest }))
  assert.equal(again.ok, true, JSON.stringify(again))
  assert.equal(v.verifyClaim(kept, call({ now, contentDigest: digest })).ok, false, 'not as of now')
  assert.equal(v.verifyClaim(kept, call({ now: at, contentDigest: Buffer.alloc(32, 8).toString('base64') })).reason, 'claim-digest')
  assert.equal(v.verifyClaim({ ...kept, head: id.head(now) }, call({ now: at, contentDigest: digest })).ok, false, 'a head of a later time')
})
