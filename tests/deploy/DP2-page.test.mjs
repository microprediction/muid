// The runnable id origin with the real page in Chrome: a person makes an identity with a passkey, authorises a
// worker's key, and the worker (muid/worker, over real HTTP) makes a request a relying party accepts, under the
// witness keys the server said to pin. A page at another origin reads the witness's answers.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:net'
import { chromium } from 'playwright-core'
import { configuration, start } from '../../deploy/id-origin.mjs'
import { newKey, enrol, request } from '../worker/impl.mjs'
import { relyingParty, memoryStore } from '../adapter/impl.mjs'
import { verifier as verifierModule } from '../impl.mjs'

const freePort = () => new Promise((resolve) => {
  const s = createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)) })
})

test('an identity made at the served page authorises a worker whose request a relying party accepts', { timeout: 120_000 }, async () => {
  const port = await freePort()
  const origin = `http://localhost:${port}`
  const s = await start(configuration({ MUID_ORIGIN: origin, MUID_DATA: mkdtempSync(join(tmpdir(), 'muid-id-origin-')), MUID_PORT: String(port) }), { log: () => {} })
  const browser = await chromium.launch({ channel: 'chrome', headless: true })
  try {
    const context = await browser.newContext()
    const page = await context.newPage()
    const problems = []
    page.on('console', (m) => { if (m.type() === 'error') problems.push(m.text()) })
    page.on('pageerror', (e) => problems.push(String(e)))
    const cdp = await context.newCDPSession(page)
    await cdp.send('WebAuthn.enable')
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
    await page.goto(origin + '/')
    assert.equal(page.url(), origin + '/id/')
    await page.fill('#name', 'trial')
    await page.click('#create-button')
    await page.waitForFunction(() => document.getElementById('status').textContent === 'Registered with the witness.')
    const identity = await page.textContent('#identity-id')

    // The worker's key, typed into the page; what the page hands back, given to the worker.
    const key = newKey()
    const aud = 'https://node.example'
    await page.fill('#agent', 'drive')
    await page.fill('#subject', key.subject)
    await page.fill('#aud', aud)
    await page.fill('#scopes', 'store.blob store.ref')
    await page.fill('#days', '7')
    await page.click('#review')
    await page.waitForSelector('#review-panel:not([hidden])')
    await page.click('#sign')
    await page.waitForSelector('#handoff:not([hidden])')
    const handOff = await page.inputValue('#handoff')
    const witness = s.url + '/witness/'
    const w = await enrol({ handOff, secret: key.secret, witness })
    assert.deepEqual([w.identity, w.aud, w.scopes], [identity, aud, ['store.blob', 'store.ref']])
    const now = Math.floor(Date.now() / 1000)
    const url = aud + '/blobs'
    const records = await request(w, key.secret, { scope: 'store.blob', method: 'PUT', url, data: { size: 1 }, at: now }, { witness })
    const rp = relyingParty({
      verifier: verifierModule.verifier({ rpId: 'localhost', origin, audience: aud, witnessKeys: s.witnessKeys, skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 }),
      store: memoryStore(),
      clock: () => now
    })
    const accepted = await rp.acceptClaim(records, { now, scope: 'store.blob', method: 'PUT', url, revoked: [] }, (r) => r.delegation.body.identity)
    assert.equal(accepted.ok, true, JSON.stringify(accepted))
    assert.equal(accepted.value, identity)

    // A page at another origin (the same server by its address, not its name) reads the witness's head.
    const other = await context.newPage()
    await other.goto(`http://127.0.0.1:${port}/id/page.css`)
    const read = await other.evaluate(async ([at, identity]) => {
      const r = await fetch(`${at}v1/identities/${identity}/head`)
      return { status: r.status, head: typeof (await r.json()).head }
    }, [origin + '/witness/', identity])
    assert.deepEqual(read, { status: 200, head: 'string' })
    assert.deepEqual(problems, [])
  } finally {
    await browser.close()
    await s.close()
  }
})
