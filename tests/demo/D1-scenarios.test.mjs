// The two-application demo's four scenarios (research/witness-api-and-demo.md), end to end: the witness service
// for heads and revocations, the transparency log with a witness cosigning its checkpoints, Forecasts accepting
// contributions through the relying-party adapter, and History reading them back from receipts alone.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, root as rootModule, verifier as verifierModule } from '../impl.mjs'
import { relyingParty, memoryStore } from '../adapter/impl.mjs'
import { witness, witnessService, memoryHoldings, tesseraLog } from '../witness/impl.mjs'
import { records as idRecords } from '../id/impl.mjs'
import { forecasts, history } from './impl.mjs'
import { make, RP_ID, ORIGIN, SECRET, KEY } from '../assertion/helpers.mjs'
import { startLog } from '../log/tessera.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const now = () => Math.floor(Date.now() / 1000)
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
const FORECASTS = 'https://forecasts.example'
const OTHER = 'https://other.example'
const W = Uint8Array.from({ length: 32 }, (_, i) => 120 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const S = Uint8Array.from({ length: 32 }, (_, i) => 200 + i)
const SERVICE_KEY = hex(ed25519.getPublicKey(S))
const WITNESS_KEYS = [{ key: WITNESS, nbf: 0, exp: 4_000_000_000 }]
const LIMITS = { skew: 60, maxLifetime: 2_592_000 }

// The owner: one passkey (simulated here; tests/id drives a real one in Chrome) and its root record.
const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)

// A worker's key, and a delegation to it signed by the owner's passkey and accepted by the worker (D6).
function worker (seed, { aud = FORECASTS, scopes = ['forecast'], lifetime = 3600, agent = 'worker' } = {}) {
  const secret = Uint8Array.from({ length: 32 }, (_, i) => seed + i)
  const d = idRecords.delegation({ agent, identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(secret)), aud, scopes, now: now(), lifetime })
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(d.id, 'hex')]), secret))
  const delegation = envelope.wrap(d.payload, { root: make({ covers: [d.id], secret: SECRET }), subject })
  // A claim for one request: POST to `path` at `origin`, with the forecast (or nothing) in `data`.
  const claim = (data, origin = aud, { scope = 'forecast', path = '/forecasts' } = {}) => {
    const { payload } = envelope.seal('claim', { delegation: d.id, scope, htm: 'POST', htu: `${origin}${path}`, at: now(), data })
    return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) })
  }
  // Its own revocation (R9): the agent retiring itself.
  const retire = () => {
    const { payload } = envelope.seal('revocation', { identity: IDENTITY, target: d.body.subject, at: now() })
    return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) })
  }
  return { id: d.id, body: d.body, agent: rootModule.agentIdOf(IDENTITY, agent), delegation, claim, retire }
}

test('the demo: limited authority, continuity, lasting attribution, revocation, an agent\'s earnings', { timeout: 300_000 }, async () => {
  const l = await startLog({ witnessed: true })
  try {
    const log = tesseraLog({ url: l.url })
    const logConfig = { origin: l.origin, log: l.vkey, cosigners: [l.cosigner], quorum: 1 }
    // The witness service holds the identity's records and signs its heads (here in process; its log is the same).
    const w = witness({ rpId: RP_ID, origin: ORIGIN, witnessKeys: WITNESS_KEYS, key: WITNESS, sign: (b) => hex(ed25519.sign(b, W)), contestWindow: 259_200, ...LIMITS })
    const ws = witnessService({ witness: w, holdings: memoryHoldings(), log, clock: now, headInterval: 0 })
    const call = async (method, path, body) => (await ws.handle(new Request('https://witness.example' + path, { method, body: body && JSON.stringify(body) }))).json()
    assert.deepEqual(await call('POST', '/v1/records', { identity: IDENTITY, type: 'root', text: rootText }), { ok: true, signed: [] })
    const head = async () => (await call('GET', `/v1/identities/${IDENTITY}/head`)).head

    // Forecasts at its origin; another service at another origin, with the same software.
    const service = (origin) => {
      const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: origin, witnessKeys: WITNESS_KEYS, maxStaleness: 86_400, maxClaimAge: 300, ...LIMITS })
      return forecasts({ origin, adapter: relyingParty({ verifier: v, store: memoryStore() }), log, checkpoints: { ...logConfig, skew: 60 }, key: SERVICE_KEY,
        sign: (b) => hex(ed25519.sign(b, S)), clock: now })
    }
    const f = service(FORECASTS)
    const other = service(OTHER)
    for (const q of ['q', 'rain', 'snow', 'hail']) f.ask(q, now() + 3600)
    other.ask('q', now() + 3600)
    // R10: the worker has the witness log its delegation once, and presents the logged record with it.
    const logs = new Map()
    const logged = async (delegation) => {
      if (!logs.has(delegation)) logs.set(delegation, (await call('POST', '/v1/delegations', { identity: IDENTITY, text: delegation })).logged)
      return logs.get(delegation)
    }
    const post = async (svc, origin, records) => {
      const body = JSON.stringify({ ...records, logged: await logged(records.delegation) })
      const res = await svc.handle(new Request(`${origin}/forecasts`, { method: 'POST', body }))
      return { status: res.status, ...(await res.json()) }
    }
    const h = history({ services: [{ origin: FORECASTS, key: SERVICE_KEY, nbf: 0, exp: 4_000_000_000 }], log: logConfig, skew: 60 })
    const contributions = async () => (await f.handle(new Request(`${FORECASTS}/contributions?identity=${IDENTITY}`))).json()

    // 1. Limited authority: the worker's delegation serves Forecasts, for its scope, once per claim.
    const w1 = worker(10)
    const h1 = await head()
    const c1 = w1.claim({ question: 'q', forecast: 7000 })
    const r1 = await post(f, FORECASTS, { claim: c1, delegation: w1.delegation, root: rootText, head: h1 })
    assert.equal(r1.status, 200, JSON.stringify(r1))
    assert.equal((await post(f, FORECASTS, { claim: c1, delegation: w1.delegation, root: rootText, head: h1 })).reason, 'replay')
    assert.equal((await post(other, OTHER, { claim: w1.claim({ question: 'q', forecast: 1000 }, OTHER), delegation: w1.delegation, root: rootText, head: h1 })).reason, 'audience')
    const reader = worker(30, { scopes: ['read'] })
    assert.equal((await post(f, FORECASTS, { claim: reader.claim({ question: 'q', forecast: 2000 }), delegation: reader.delegation, root: rootText, head: h1 })).reason, 'scope')

    // 2. Continuity: the worker's key is replaced (a new delegation, the same identity); History shows one contributor.
    const w2 = worker(50)
    const r2 = await post(f, FORECASTS, { claim: w2.claim({ question: 'q', forecast: 4000 }), delegation: w2.delegation, root: rootText, head: h1 })
    assert.equal(r2.status, 200, JSON.stringify(r2))
    const seen = h.verify(IDENTITY, await contributions(), now())
    assert.deepEqual(seen.refused, [])
    assert.deepEqual(seen.accepted.map((a) => [a.identity, a.delegation]), [[IDENTITY, w1.id], [IDENTITY, w2.id]])
    for (const a of seen.accepted) assert.ok(a.at <= a.existedBy + 60 && a.existedBy <= now() + 60, 'the cosigner vouches for when it existed')

    // 3. Lasting attribution: long after the delegations expire, the claims no longer verify but the receipts do.
    const later = w2.body.exp + 365 * 86_400
    const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: FORECASTS, witnessKeys: WITNESS_KEYS, maxStaleness: 86_400, maxClaimAge: 300, ...LIMITS })
    const stale = v.verifyClaim({ claim: c1, delegation: w1.delegation, root: rootText, head: h1 }, { now: later, scope: 'forecast', method: 'POST', url: `${FORECASTS}/forecasts`, revoked: [] })
    assert.equal(stale.ok, false)
    assert.deepEqual(h.verify(IDENTITY, await contributions(), later).accepted.length, 2)
    // A History that does not pin Forecasts accepts none; a bundle for another identity is not this one's.
    assert.deepEqual(history({ services: [], log: logConfig, skew: 60 }).verify(IDENTITY, await contributions(), now()).refused.map((r) => r.reason), ['service', 'service'])
    assert.deepEqual(h.verify('f'.repeat(64), await contributions(), now()).refused.map((r) => r.reason), ['identity', 'identity'])

    // 4. Revocation: the owner revokes w2; the next head carries it. An honest request carrying that head moves
    // Forecasts' memory forward, so w2 is refused at once, even with the older head it still holds.
    await sleep(1100) // a later second, so the new head is newer
    const revocation = envelope.seal('revocation', { identity: IDENTITY, target: w2.id, at: now() })
    const revText = envelope.wrap(revocation.payload, { root: ROOT, assertion: make({ covers: [revocation.id], secret: SECRET }) })
    assert.deepEqual(await call('POST', '/v1/revocations', { identity: IDENTITY, text: revText }), { ok: true, signed: [] })
    const h2 = await head()
    assert.deepEqual(Array.from(envelope.open(h2, 'head').body.revoked), [w2.id])
    const w3 = worker(70)
    assert.equal((await post(f, FORECASTS, { claim: w3.claim({ question: 'q', forecast: 5000 }), delegation: w3.delegation, root: rootText, head: h2 })).status, 200)
    assert.equal((await post(f, FORECASTS, { claim: w2.claim({ question: 'q', forecast: 9000 }), delegation: w2.delegation, root: rootText, head: h1 })).reason, 'stale')
    assert.equal((await post(f, FORECASTS, { claim: w2.claim({ question: 'q', forecast: 9000 }), delegation: w2.delegation, root: rootText, head: h2 })).reason, 'revoked')
    // Its earlier contribution stays attributed: revocation stops new claims, it does not rewrite history.
    assert.equal(h.verify(IDENTITY, await contributions(), now()).accepted.length, 3)

    // 5. The organizing example: log in, authorise a temporary agent, let it contribute, retire it, and collect its
    // later earnings under the continuing identity. The beneficiary was bound when each contribution was accepted.
    await sleep(1100)
    const agent = worker(90, { lifetime: 3600, agent: 'temporary' })
    const h3 = await head()
    for (const [question, forecast] of [['rain', 8000], ['snow', 1000]]) {
      assert.equal((await post(f, FORECASTS, { claim: agent.claim({ question, forecast }), delegation: agent.delegation, root: rootText, head: h3 })).status, 200)
    }
    assert.deepEqual(await call('POST', '/v1/revocations', { identity: IDENTITY, text: agent.retire(), delegation: agent.delegation }), { ok: true, signed: [] })
    await sleep(1100)
    const h4 = await head()
    assert.ok(Array.from(envelope.open(h4, 'head').body.revoked).includes(agent.body.subject), 'retired: the next head carries it')
    assert.equal((await post(f, FORECASTS, { claim: agent.claim({ question: 'hail', forecast: 1 }), delegation: agent.delegation, root: rootText, head: h4 })).reason, 'revoked')
    // The questions resolve after the agent is gone; its earnings arrive under the identity.
    assert.equal(f.resolve('rain', 1), 1)
    assert.equal(f.resolve('snow', 0), 1)
    const earned = (10_000 - 2000 ** 2 / 10_000) + (10_000 - 1000 ** 2 / 10_000)
    const e = await (await f.handle(new Request(`${FORECASTS}/earnings?identity=${IDENTITY}`))).json()
    assert.deepEqual(e.agents.find((a) => a.agent === agent.agent), { agent: agent.agent, name: agent.body.agent, contributions: 2, earned })
    // The owner's own device collects; the retired agent cannot.
    const device = worker(110, { scopes: ['collect'] })
    const collect = async (w, h) => (await f.handle(new Request(`${FORECASTS}/collect`, { method: 'POST',
      body: JSON.stringify({ claim: w.claim({}, FORECASTS, { scope: 'collect', path: '/collect' }), delegation: w.delegation, root: rootText, head: h, logged: await logged(w.delegation) }) }))).json()
    assert.equal((await collect(agent, h4)).reason, 'revoked')
    assert.deepEqual(await collect(device, h4), { ok: true, collected: e.balance })
    assert.equal((await (await f.handle(new Request(`${FORECASTS}/earnings?identity=${IDENTITY}`))).json()).balance, 0)
  } finally {
    await l.stop()
  }
})
