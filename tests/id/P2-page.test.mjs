// The id page in Chrome, with a virtual authenticator (Chrome DevTools Protocol, WebAuthn domain): an identity is
// created, a worker authorised by one assertion, and what the page hands the worker, once the worker consents,
// verifies under the core — through the witness's head and the relying party's verifier.
import { test as nodeTest, after } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { chromium } from 'playwright-core'
import { generateKeyPairSync } from 'node:crypto'
import { root as rootModule, delegation as delegationModule, assertion as assertionModule, envelope, verifier as verifierModule } from '../impl.mjs'
import { witness, witnessService, memoryHoldings, memoryLog } from '../witness/impl.mjs'
import { serve } from './serve.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const WORKER = Uint8Array.from({ length: 32 }, (_, i) => 77 + i)
const SUBJECT = hex(ed25519.getPublicKey(WORKER))
const W = Uint8Array.from({ length: 32 }, (_, i) => 120 + i)
const WITNESS = hex(ed25519.getPublicKey(W))

// Under mutation testing (the dry run included) and the broken twins (their control run included), one failing test
// settles the run, and a broken page shows itself within seconds. So there, every wait is cut to 15 s and every test to
// 60 s, and once a test fails or times out, the tests after it fail at once rather than each waiting out its limits.
// The unbroken runs use the same limits, so they are seen to suffice.
const FAIL_FAST = globalThis.__stryker__ !== undefined || process.env.MUID_FAIL_FAST === '1'
const WAIT = 15_000
let failed = false
function test (name, opts, fn) {
  if (!FAIL_FAST) return nodeTest(name, opts, fn)
  return nodeTest(name, { ...opts, timeout: Math.min(opts.timeout, 60_000) }, async (t) => {
    if (failed) throw new Error('an earlier test failed')
    // The signal is aborted when the test ends however it ends: only an abort while it is still running is a timeout.
    let running = true
    t.signal.addEventListener('abort', () => { if (running) failed = true })
    try { return await fn(t) } catch (e) { failed = true; throw e } finally { running = false }
  })
}

// A site serving the page and a witness service (in memory, its contest window a minute, its clock movable), and a
// browser with one device; `device()` adds another, with its own profile and authenticator.
// A test that fails or times out does not reach its own close: what it opened is closed when the file ends, so the
// process exits and the failure is reported. Closing a browser that has stopped answering never returns, so closing is
// given a minute: past it the hook fails, naming what was left open, and the runner's forced exit ends the file.
const opened = new Set()
const CLOSE_WITHIN = 60_000
after(async () => {
  const late = new Promise((resolve) => setTimeout(resolve, CLOSE_WITHIN, 'late').unref())
  const closed = Promise.all([...opened].map((end) => end()))
  if (await Promise.race([closed, late]) === 'late') throw new Error(`${opened.size} browser(s) still open ${CLOSE_WITHIN / 1000}s after the last test`)
})

async function open ({ init } = {}) {
  const holder = {}
  const keys = [{ key: WITNESS, nbf: 0, exp: 4_000_000_000 }]
  const site = await serve({ witness: { handle: (r) => holder.svc.handle(r) }, witnessKeys: keys })
  let offset = 0
  const clock = () => Math.floor(Date.now() / 1000) + offset
  const w = witness({ rpId: 'localhost', origin: site.origin, witnessKeys: keys, key: WITNESS, sign: (b) => hex(ed25519.sign(b, W)),
    contestWindow: 60, skew: 60, maxLifetime: 2_592_000 })
  const real = witnessService({ witness: w, holdings: memoryHoldings(), log: memoryLog(), clock, headInterval: 0 })
  holder.svc = real
  const browser = await chromium.launch({ channel: 'chrome', headless: true })
  const end = async () => { opened.delete(end); await browser.close(); site.close() }
  opened.add(end)
  const problems = []
  const pages = []
  // Chrome warns that only ES256 is offered: deliberate (I6), and the only warning allowed.
  const ES256_ONLY = /^publicKey\.pubKeyCredParams is missing at least one of the default algorithm identifiers: ES256 and RS256\./
  function watched (page) {
    page.on('console', (m) => { if ((m.type() === 'error' || m.type() === 'warning') && !ES256_ONLY.test(m.text())) problems.push(m.text()) })
    page.on('pageerror', (e) => problems.push(String(e)))
    return page
  }
  // Another tab of a device's browser: the same storage, no authenticator of its own.
  async function tab (context, url = site.origin + '/id/') {
    const page = watched(await context.newPage())
    await page.goto(url)
    pages.push(page)
    return page
  }
  async function device () {
    const context = await browser.newContext()
    if (FAIL_FAST) context.setDefaultTimeout(WAIT)
    // Under mutation testing, the mutant the runner activated is activated in the page too: Stryker's instrumented
    // code reads it from process.env in Node, which a page has not.
    const mutant = process.env.__STRYKER_ACTIVE_MUTANT__
    if (mutant !== undefined) await context.addInitScript((m) => { globalThis.__stryker__ = { activeMutant: m } }, mutant)
    if (init !== undefined) await context.addInitScript(init)
    const page = watched(await context.newPage())
    const cdp = await context.newCDPSession(page)
    await cdp.send('WebAuthn.enable')
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
    await page.goto(site.origin + '/id/')
    pages.push(page)
    return { context, page, cdp, authenticatorId }
  }
  // Under mutation testing's first run, the pages' coverage is added to this process's, which the runner reads.
  const collect = async () => {
    const ns = globalThis.__stryker__
    if (ns === undefined) return
    for (const frame of pages.flatMap((p) => p.frames())) {
      const cov = await frame.evaluate(() => globalThis.__stryker__?.mutantCoverage).catch(() => undefined)
      if (cov === undefined) continue
      ns.mutantCoverage ??= { static: {}, perTest: {} }
      for (const [id, n] of Object.entries(cov.static)) ns.mutantCoverage.static[id] = (ns.mutantCoverage.static[id] ?? 0) + n
    }
  }
  const first = await device()
  // What the witness itself holds, whatever the page is shown (an outage or a refusing witness stands in front of it).
  const witnessGet = async (path) => (await real.handle(new Request('http://witness' + path))).json()
  const witnessPost = async (path, body) => (await real.handle(new Request('http://witness' + path, { method: 'POST', body: JSON.stringify(body) }))).json()
  // `refusing(true)` puts a witness that refuses everything in front of the real one, as a test of the page's errors.
  const refusing = (on) => { holder.svc = on ? { handle: async () => Response.json({ ok: false, reason: 'test' }, { status: 422 }) } : real }
  // `outage('down')`: the witness is unreachable; `outage('lost')`: it takes each request, but its answer is lost.
  const outage = (kind) => {
    const unavailable = () => Response.json({ ok: false, reason: 'unavailable' }, { status: 503 })
    holder.svc = kind === 'down' ? { handle: async () => unavailable() } : kind === 'lost' ? { handle: async (r) => { await real.handle(r); return unavailable() } } : real
  }
  return { site, browser, ...first, device, tab, problems, collect, keys, clock, witnessGet, witnessPost, svc: real, refusing, outage, advance: (s) => { offset += s },
    close: async () => { await collect(); await end() } }
}

const errorShown = (page) => page.waitForFunction(() => document.getElementById('error').textContent !== '')

async function createIdentity (page, name = 'test') {
  await page.fill('#name', name)
  await page.click('#create-button')
  await page.waitForSelector('#identity:not([hidden])')
  await page.waitForFunction(() => document.getElementById('status').textContent === 'Registered with the witness.')
  return { text: await page.inputValue('#root-text'), identity: await page.textContent('#identity-id') }
}

async function authorise (page, { agent = 'forecaster', subject = SUBJECT, aud = 'https://app.example', scopes = 'post read', days = '1' } = {}) {
  await page.fill('#agent', agent)
  await page.fill('#subject', subject)
  await page.fill('#aud', aud)
  await page.fill('#scopes', scopes)
  await page.fill('#days', days)
  await page.click('#review')
}

test('create an identity and authorise a worker: the core, the witness and the verifier accept the result', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const r = await createIdentity(t.page)
    const c = rootModule.checkRoot(r.text, { rpId })
    assert.equal(c.ok, true, JSON.stringify(c))
    assert.equal(r.identity, rootModule.identityOf(c.id))
    assert.equal(await t.page.isHidden('#create'), true)
    // A resident credential (a passkey), user-verified, named as the user asked; the record kept under muid.root.
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    assert.equal(credentials.length, 1)
    assert.equal(credentials[0].isResidentCredential, true)
    assert.equal(credentials[0].userName, 'test')
    assert.equal(JSON.parse(await t.page.evaluate(() => localStorage.getItem('muid.root'))).text, r.text)

    // Surrounding spaces are not part of what is signed.
    await authorise(t.page, { agent: ' forecaster ', subject: ` ${SUBJECT} `, aud: ' https://app.example ', scopes: ' post  read ' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-agent'), 'forecaster')
    assert.equal(await t.page.textContent('#show-aud'), 'https://app.example')
    assert.equal(await t.page.textContent('#show-scopes'), 'post read')
    assert.equal(await t.page.textContent('#show-subject'), SUBJECT)
    const exp = Date.parse(await t.page.textContent('#show-exp')) / 1000
    assert.ok(Math.abs(exp - (Date.now() / 1000 + 86_400)) < 120)
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    const h = JSON.parse(await t.page.inputValue('#handoff'))
    // Reviewing again withdraws what was handed over until it is signed again.
    await t.page.click('#review')
    assert.equal(await t.page.isHidden('#handoff'), true)

    // The worker consents (D6) and has a delegation the core accepts.
    const id = envelope.open(envelope.wrap(h.payload, { root: h.root, subject: '0'.repeat(128) }), 'delegation').id
    const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id, 'hex')]), WORKER))
    const text = envelope.wrap(h.payload, { root: h.root, subject })
    const now = Math.floor(Date.now() / 1000)
    const d = delegationModule.checkDelegation(text, { rootKey: c.key, rpId, origin: t.site.origin, now, skew: 60, maxLifetime: 2_592_000 })
    assert.equal(d.ok, true, JSON.stringify(d))

    // The page registered the root with the witness, which signs a head; the worker has the witness log its
    // delegation (R10); a relying party at the audience accepts it.
    const { head } = await t.witnessGet(`/v1/identities/${r.identity}/head`)
    const { logged } = await t.witnessPost('/v1/delegations', { identity: r.identity, text })
    const v = verifierModule.verifier({ rpId, origin: t.site.origin, audience: 'https://app.example', witnessKeys: t.keys, skew: 60,
      maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
    const accepted = v.verifyDelegation({ delegation: text, root: r.text, head, logged }, { now, scope: 'post', revoked: [] })
    assert.equal(accepted.ok, true, JSON.stringify(accepted))
    assert.deepEqual(t.problems, [])

    // The identity is remembered on this browser.
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await t.page.textContent('#identity-id'), r.identity)
  } finally {
    await t.close()
  }
})

test('I4: what is shown is what is signed; any change withdraws it, and refusals are shown', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    await authorise(t.page, { aud: 'https://App.example' })
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'the audience must be an origin, such as https://app.example')
    assert.equal(await t.page.isHidden('#review-panel'), true)
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#error'), '')
    await t.page.fill('#scopes', 'admin')
    assert.equal(await t.page.isHidden('#review-panel'), true, 'an edit withdraws the reviewed delegation')
    await t.page.evaluate(() => document.getElementById('sign').click())
    assert.equal(await t.page.isHidden('#handoff'), true, 'nothing is signed without a review')
    assert.equal(await t.page.textContent('#error'), '')
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.fill('#agent', 'scorer')
    assert.equal(await t.page.isHidden('#review-panel'), true, 'renaming the agent withdraws it too')
    await authorise(t.page, { agent: 'My agent' })
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), "the agent's name must be a lower-case name, such as forecaster")
    await authorise(t.page, { subject: 'x' })
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), "the worker's key must be an Ed25519 public key, 64 hex digits")
  } finally {
    await t.close()
  }
})

test('the assertion requires user verification: without it, nothing is handed over', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    // The passkey moves to an authenticator that cannot verify the user: asked to prefer verification it would sign
    // without; required to, it refuses.
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    await t.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: t.authenticatorId })
    const { authenticatorId } = await t.cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: false, automaticPresenceSimulation: true } })
    await t.cdp.send('WebAuthn.addCredential', { authenticatorId, credential: credentials[0] })
    await t.page.click('#sign')
    await t.page.waitForFunction(() => document.getElementById('error').textContent !== '')
    assert.equal(await t.page.textContent('#error'), 'The passkey request was cancelled.')
    assert.equal(await t.page.isHidden('#handoff'), true)
    // Back on an authenticator that verifies the user, signing again hands it over, and the error is gone.
    await t.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId })
    const again = await t.cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
    await t.cdp.send('WebAuthn.addCredential', { authenticatorId: again.authenticatorId, credential: credentials[0] })
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    assert.equal(await t.page.textContent('#error'), '')
  } finally {
    await t.close()
  }
})

test('an edit while the passkey is signing withdraws the delegation: the late signature is not handed over', { timeout: 120_000 }, async () => {
  // The passkey answers half a second late, so the edit lands while it is being asked.
  const t = await open({ init: () => {
    const get = navigator.credentials.get.bind(navigator.credentials)
    navigator.credentials.get = async (o) => { await new Promise((resolve) => setTimeout(resolve, 500)); return get(o) }
  } })
  try {
    await createIdentity(t.page)
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.click('#sign')
    await t.page.fill('#scopes', 'admin')
    await t.page.waitForTimeout(1500)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.equal(await t.page.inputValue('#handoff'), '')
  } finally {
    await t.close()
  }
})

test("with another passkey for this site on the device, the identity's own signs", { timeout: 120_000 }, async () => {
  // The options the page asks with are recorded: which credential signs when none is named is the browser's choice.
  const t = await open({ init: () => {
    const get = navigator.credentials.get.bind(navigator.credentials)
    navigator.credentials.get = (o) => { globalThis.asked = o.publicKey.allowCredentials.map((c) => [c.type, btoa(String.fromCharCode(...new Uint8Array(c.id)))]); return get(o) }
  } })
  try {
    // Other passkeys for this site, held before and after the identity's own.
    const add = (n) => t.cdp.send('WebAuthn.addCredential', { authenticatorId: t.authenticatorId, credential: { credentialId: Buffer.from(`other passkey ${n}`).toString('base64'),
      isResidentCredential: true, rpId: 'localhost', userHandle: Buffer.from(`other ${n}`).toString('base64'), signCount: 0,
      privateKey: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') } })
    await add(1)
    const r = await createIdentity(t.page)
    await add(2)
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    const h = JSON.parse(await t.page.inputValue('#handoff'))
    const own = JSON.parse(await t.page.evaluate(() => localStorage.getItem('muid.root'))).credential
    assert.deepEqual(await t.page.evaluate(() => globalThis.asked), [['public-key', Buffer.from(own, 'base64url').toString('base64')]])
    const key = rootModule.checkRoot(r.text, { rpId: 'localhost' }).key
    const id = h.root.covers[0]
    assert.deepEqual({ ...assertionModule.checkRootAssertion(h.root, { record: id, rpId: 'localhost', origin: t.site.origin, key }) }, { ok: true })
  } finally {
    await t.close()
  }
})

test('an unreadable stored identity is forgotten: the page offers to create one', { timeout: 120_000 }, async () => {
  const t = await open({ init: () => { if (!sessionStorage.getItem('seeded')) { sessionStorage.setItem('seeded', '1'); localStorage.setItem('muid.root', '{') } } })
  try {
    await t.page.reload()
    await t.page.waitForSelector('#create:not([hidden])')
    assert.equal(await t.page.isHidden('#identity'), true)
    assert.equal(await t.page.isHidden('#authorise'), true)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('a stored root of the wrong form is forgotten, not shown', { timeout: 120_000 }, async () => {
  const t = await open({ init: () => { if (!sessionStorage.getItem('seeded')) { sessionStorage.setItem('seeded', '1'); localStorage.setItem('muid.root', '{"identity":"<b>x</b>","text":5}') } } })
  try {
    await t.page.reload()
    await t.page.waitForSelector('#create:not([hidden])')
    assert.equal(await t.page.isHidden('#identity'), true)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Found by review: a tab opened before the identity was made still offered to create one, and overwrote it.
test('another tab that creates an identity is followed here, and one is never created over it', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    const other = await t.tab(t.context)
    await other.waitForSelector('#create:not([hidden])')
    await t.page.bringToFront() // WebAuthn asks only a focused document
    const a = await createIdentity(t.page)
    // The other tab, open since before, now shows the identity and offers no create.
    await other.waitForSelector('#identity:not([hidden])')
    assert.equal(await other.textContent('#identity-id'), a.identity)
    assert.equal(await other.isHidden('#create'), true)
    // A create begun in a tab that has not yet heard of it adopts the stored identity and creates nothing.
    await other.evaluate(() => { const r = localStorage.getItem('muid.root'); localStorage.removeItem('muid.root'); window.dispatchEvent(new StorageEvent('storage', { key: 'muid.root', newValue: null })); localStorage.setItem('muid.root', r) })
    await other.waitForSelector('#create:not([hidden])')
    await other.click('#create-button')
    await other.waitForSelector('#identity:not([hidden])')
    assert.equal(await other.textContent('#identity-id'), a.identity)
    assert.equal(JSON.parse(await t.page.evaluate(() => localStorage.getItem('muid.root'))).identity, a.identity, 'not overwritten')
    // A review open in the other tab is withdrawn when what is stored changes; storage cleared there is followed too.
    await other.fill('#agent', 'forecaster')
    await other.fill('#subject', SUBJECT)
    await other.fill('#aud', 'https://app.example')
    await other.fill('#scopes', 'post')
    await other.click('#review')
    await other.waitForSelector('#review-panel:not([hidden])')
    // Another key of this origin changing is not the identity changing: the review stays. (A listener added after the
    // page's runs after it, so once it has seen the event the page has handled it.)
    await other.evaluate(() => { window.seen = []; window.addEventListener('storage', (e) => window.seen.push(e.key)) })
    await t.page.evaluate(() => localStorage.setItem('unrelated', '1'))
    await other.waitForFunction(() => window.seen.includes('unrelated'))
    assert.equal(await other.isHidden('#review-panel'), false, 'another key leaves the review')
    await t.page.evaluate(() => localStorage.setItem('muid.root', JSON.stringify({ ...JSON.parse(localStorage.getItem('muid.root')), note: 1 })))
    await other.waitForSelector('#review-panel', { state: 'hidden' })
    await t.page.evaluate(() => localStorage.clear())
    await other.waitForSelector('#create:not([hidden])')
    assert.equal(await other.isHidden('#identity'), true)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// SPEC §8: root registration and every root-signed action happen in a top-level window. The headers refuse framing;
// here they are removed, and the framed page still offers nothing to click.
test('framed, the page offers nothing and says to open it in its own window', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    // A registration left pending (the witness was down) is not sent from a frame.
    t.outage('down')
    await t.page.fill('#name', 'test')
    await t.page.click('#create-button')
    await t.page.waitForSelector('#pending:not([hidden])')
    const identity = await t.page.textContent('#identity-id')
    t.outage(null)
    await t.context.route('**/id/**', async (route) => {
      const r = await route.fetch()
      const headers = { ...r.headers() }
      delete headers['x-frame-options']
      delete headers['content-security-policy']
      await route.fulfill({ response: r, headers })
    })
    // A page of this origin (so the frame shares its storage, unpartitioned) and no CSP of its own.
    await t.context.route(t.site.origin + '/outer', (route) => route.fulfill({ contentType: 'text/html', body: '<!doctype html><body></body>' }))
    const outer = await t.tab(t.context, t.site.origin + '/outer')
    await outer.evaluate((src) => { const f = document.createElement('iframe'); f.src = src; document.body.append(f) }, t.site.origin + '/id/')
    const frame = await (await outer.waitForSelector('iframe')).contentFrame()
    await frame.waitForSelector('#error', { state: 'attached' })
    await frame.waitForFunction(() => document.getElementById('error').textContent !== '')
    assert.equal(await frame.textContent('#error'), 'This page acts only in its own window: open it directly.')
    for (const id of ['create', 'joining', 'identity', 'add-root', 'authorise']) assert.equal(await frame.isHidden('#' + id), true, id)
    await outer.waitForLoadState('networkidle')
    assert.deepEqual(await t.witnessGet(`/v1/identities/${identity}/records`), { ok: false, reason: 'unknown-identity' }, 'nothing registered')
    // The same page, not framed, sends the pending registration.
    await t.collect()
    await t.page.reload()
    await t.page.waitForFunction(() => document.getElementById('status').textContent === 'Registered with the witness.')
  } finally {
    await t.close()
  }
})

// SPEC §8: the rp ID and origin are deployment configuration. The same page served under another origin (here the
// server's address rather than its configured name) makes nothing, registers nothing, and says where to open it.
test('under an origin other than its configured one, the page offers nothing and says where it acts', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    const elsewhere = await t.tab(t.context, t.site.origin.replace('localhost', '127.0.0.1') + '/id/')
    await elsewhere.waitForFunction(() => document.getElementById('error').textContent !== '')
    assert.equal(await elsewhere.textContent('#error'), `This page acts only at ${t.site.origin}: open it there.`)
    for (const id of ['create', 'joining', 'identity', 'add-root', 'authorise']) assert.equal(await elsewhere.isHidden('#' + id), true, id)
    assert.equal(await t.page.isHidden('#create'), false, 'at its own origin it offers to create an identity')
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('a passkey that refuses (no user verification) is reported, and nothing is created', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    await t.cdp.send('WebAuthn.setUserVerified', { authenticatorId: t.authenticatorId, isUserVerified: false })
    await t.page.click('#create-button')
    await t.page.waitForFunction(() => document.getElementById('error').textContent !== '')
    assert.equal(await t.page.textContent('#error'), 'The passkey request was cancelled.')
    assert.equal(await t.page.isHidden('#identity'), true)
    assert.equal(await t.page.isHidden('#authorise'), true)
    // Allowed again, the next attempt clears the message; an empty name falls back to a default.
    await t.cdp.send('WebAuthn.setUserVerified', { authenticatorId: t.authenticatorId, isUserVerified: true })
    await createIdentity(t.page, '  ')
    assert.equal(await t.page.textContent('#error'), '')
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    assert.equal(credentials[0].userName, 'muid identity')
  } finally {
    await t.close()
  }
})

test('a second passkey: one device adds it, the other co-signs; once settled it authorises a worker the verifier accepts', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const a = await createIdentity(t.page)
    const b = await t.device()
    await b.page.click('#join-button')
    await b.page.waitForSelector('#joining:not([hidden])')
    assert.equal(await b.page.isHidden('#identity'), true)
    const bRoot = await b.page.inputValue('#join-root')
    const bId = rootModule.checkRoot(bRoot, { rpId }).id
    // Its fingerprint, to compare with what the other device shows before signing.
    const print = bId.slice(0, 24).match(/.{4}/g).join(' ')
    assert.equal(await b.page.textContent('#join-fingerprint'), print)
    // A joining passkey is never registered as an identity of its own, not even when the page loads again.
    await t.collect()
    await b.page.reload()
    await b.page.waitForSelector('#joining:not([hidden])')
    await b.page.waitForLoadState('networkidle')
    assert.equal((await t.witnessGet(`/v1/identities/${rootModule.identityOf(bId)}/records`)).ok, false)

    // On the first device: what is added is shown, and an edit withdraws it.
    await t.page.fill('#new-root', 'x')
    await t.page.click('#add-review')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'that is not a root record: envelope-encoding')
    await t.page.fill('#new-root', ` ${bRoot} `)
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    assert.equal(await t.page.textContent('#add-added'), bId)
    assert.equal(await t.page.textContent('#add-fingerprint'), print, 'the same fingerprint as on the joining device')
    assert.equal(await t.page.textContent('#add-epoch'), '2')
    await t.page.fill('#new-root', bRoot + ' ')
    assert.equal(await t.page.isHidden('#add-panel'), true, 'an edit withdraws the change')
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    await t.page.click('#add-sign')
    await t.page.waitForSelector('#add-handoff:not([hidden])')
    const payload = await t.page.inputValue('#add-handoff')
    const change = envelope.open(envelope.wrap(payload, {}), 'membership')
    assert.deepEqual(Array.from(change.body.roots), [rootModule.checkRoot(a.text, { rpId }).id, bId].sort())

    // On the second device: a change that does not add it is refused; this one is shown, then co-signed.
    const elsewhere = envelope.seal('membership', { ...change.body, roots: [rootModule.checkRoot(a.text, { rpId }).id] }).payload
    await b.page.fill('#cosign-payload', elsewhere)
    await b.page.click('#cosign-review')
    await errorShown(b.page)
    assert.equal(await b.page.textContent('#error'), 'that change does not add this passkey')
    await b.page.fill('#cosign-payload', 'x')
    await b.page.click('#cosign-review')
    assert.equal(await b.page.textContent('#error'), 'that is not a membership change')
    await b.page.fill('#cosign-payload', payload)
    await b.page.click('#cosign-review')
    await b.page.waitForSelector('#cosign-panel:not([hidden])')
    assert.equal(await b.page.textContent('#cosign-identity'), a.identity)
    assert.equal(await b.page.textContent('#cosign-roots'), Array.from(change.body.roots).join(' '))
    await b.page.click('#cosign-sign')
    await b.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await b.page.textContent('#identity-id'), a.identity)
    // Co-signed, it is part of the identity: nothing is pending, and a reload registers nothing.
    await t.collect()
    await b.page.reload()
    await b.page.waitForSelector('#identity:not([hidden])')
    await b.page.waitForLoadState('networkidle')
    assert.deepEqual([await b.page.isHidden('#pending'), await b.page.textContent('#status')], [true, ''])

    // The witness anchored the change: pending; the new root has no authority until it settles.
    const held = await t.witnessGet(`/v1/identities/${a.identity}/records`)
    assert.equal(held.anchors.length, 1)
    await authorise(b.page)
    await errorShown(b.page)
    assert.equal(await b.page.textContent('#error'), 'this passkey has no authority yet: wait for the change to settle')
    t.advance(61)
    assert.equal((await t.svc.tick()).length, 1, 'the settlement, once the window has passed')

    // Now the second passkey authorises a worker, under the settled membership; the verifier accepts it.
    await authorise(b.page)
    await b.page.waitForSelector('#review-panel:not([hidden])')
    await b.page.click('#sign')
    await b.page.waitForSelector('#handoff:not([hidden])')
    const h = JSON.parse(await b.page.inputValue('#handoff'))
    const id = envelope.open(envelope.wrap(h.payload, { root: h.root, subject: '0'.repeat(128) }), 'delegation')
    assert.equal(id.body.membership, change.id)
    const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(id.id, 'hex')]), WORKER))
    const text = envelope.wrap(h.payload, { root: h.root, subject })
    const { head } = await t.witnessGet(`/v1/identities/${a.identity}/head`)
    const { logged } = await t.witnessPost('/v1/delegations', { identity: a.identity, text })
    const v = verifierModule.verifier({ rpId, origin: t.site.origin, audience: 'https://app.example', witnessKeys: t.keys, skew: 60,
      maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
    const accepted = v.verifyDelegation({ delegation: text, root: bRoot, head, logged }, { now: t.clock(), scope: 'post', revoked: [] })
    assert.equal(accepted.ok, true, JSON.stringify(accepted))
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('signing buttons do nothing before a review; the witness refusing is shown; a retry clears it', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    // A fresh page shows only creation.
    for (const id of ['#identity', '#add-root', '#authorise', '#joining']) assert.equal(await t.page.isHidden(id), true, id)
    const a = await createIdentity(t.page)
    for (const id of ['#sign', '#add-sign']) {
      await t.page.evaluate((x) => document.querySelector(x).click(), id)
      assert.equal(await t.page.textContent('#error'), '', `${id} before any review`)
    }
    const b = await t.device()
    await b.page.click('#join-button')
    await b.page.waitForSelector('#joining:not([hidden])')
    for (const id of ['#identity', '#add-root', '#authorise']) assert.equal(await b.page.isHidden(id), true, `joining: ${id}`)
    await b.page.evaluate(() => document.getElementById('cosign-sign').click())
    assert.equal(await b.page.textContent('#error'), '')
    const bRoot = await b.page.inputValue('#join-root')
    // The joining passkey is not registered as an identity of its own.
    const own = rootModule.identityOf(rootModule.checkRoot(bRoot, { rpId: 'localhost' }).id)
    assert.equal((await t.svc.handle(new Request(`http://witness/v1/identities/${own}/records`))).status, 404)

    // The witness refuses the change: shown; once it accepts, the retry clears the message.
    await t.page.fill('#new-root', bRoot)
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    t.refusing(true)
    await t.page.click('#add-sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'the witness refused the membership: test')
    t.refusing(false)
    await t.page.click('#add-sign')
    await t.page.waitForSelector('#add-handoff:not([hidden])')
    assert.equal(await t.page.textContent('#error'), '')
    assert.equal(await t.page.textContent('#status'), 'Signed. The other device co-signs this change.')
    // Reviewing again withdraws what was handed over.
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    assert.equal(await t.page.isHidden('#add-handoff'), true)
    const payload = JSON.parse(JSON.stringify(await t.page.inputValue('#add-handoff')))

    // The same on the co-signing device; surrounding spaces in what is pasted are not part of it.
    await b.page.fill('#cosign-payload', `  ${payload}  `)
    await b.page.click('#cosign-review')
    await b.page.waitForSelector('#cosign-panel:not([hidden])')
    t.refusing(true)
    await b.page.click('#cosign-sign')
    await errorShown(b.page)
    assert.equal(await b.page.textContent('#error'), 'the witness refused the membership: test')
    await b.page.click('#cosign-review')
    assert.equal(await b.page.textContent('#error'), '', 'a new review clears the message')
    await b.page.click('#cosign-sign')
    await errorShown(b.page)
    t.refusing(false)
    await b.page.click('#cosign-sign') // signed again, with no new review: the message goes when it succeeds
    await b.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await b.page.textContent('#error'), '')
    assert.equal(await b.page.textContent('#status'), 'Co-signed. The change settles once its contest window has passed.')
    assert.equal(await b.page.textContent('#identity-id'), a.identity)
    // The joined identity is remembered; on a reloaded page the signing buttons still do nothing before a review.
    await t.collect()
    await b.page.reload()
    await b.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await b.page.textContent('#identity-id'), a.identity)
    for (const id of ['#sign', '#add-sign']) {
      await b.page.evaluate((x) => document.querySelector(x).click(), id)
      assert.equal(await b.page.textContent('#error'), '', `${id} on a reloaded page`)
    }
    // The browser reports each refusal this test caused; nothing else.
    assert.deepEqual(t.problems.filter((p) => !/status of 422 \(Unprocessable Entity\)$/.test(p)), [])
    assert.equal(t.problems.length, 3)
  } finally {
    await t.close()
  }
})

test('a change edited while the passkey is signing is not submitted, on either device', { timeout: 180_000 }, async () => {
  const t = await open({ init: () => {
    const get = navigator.credentials.get.bind(navigator.credentials)
    navigator.credentials.get = async (o) => { await new Promise((resolve) => setTimeout(resolve, 500)); return get(o) }
  } })
  try {
    const a = await createIdentity(t.page)
    const b = await t.device()
    await b.page.click('#join-button')
    await b.page.waitForSelector('#joining:not([hidden])')
    const bRoot = await b.page.inputValue('#join-root')
    await t.page.fill('#new-root', bRoot)
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    await t.page.click('#add-sign')
    await t.page.fill('#new-root', bRoot + ' ')
    await t.page.waitForTimeout(1500)
    assert.equal((await t.witnessGet(`/v1/identities/${a.identity}/records`)).memberships.length, 0)
    // Signed properly, then the co-signer edits while its passkey is asked.
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    await t.page.click('#add-sign')
    await t.page.waitForSelector('#add-handoff:not([hidden])')
    await b.page.fill('#cosign-payload', await t.page.inputValue('#add-handoff'))
    await b.page.click('#cosign-review')
    await b.page.waitForSelector('#cosign-panel:not([hidden])')
    await b.page.click('#cosign-sign')
    await b.page.fill('#cosign-payload', 'x')
    await b.page.waitForTimeout(1500)
    assert.equal((await t.witnessGet(`/v1/identities/${a.identity}/records`)).memberships.length, 1, "only the first device's signature")
    assert.equal(await b.page.isHidden('#identity'), true)
  } finally {
    await t.close()
  }
})

// Issue #34: the passkey and its root are kept before the witness is asked to register the root, so a failed
// registration leaves a pending state with a retry, which sends the same root (no new passkey); a lost answer is
// recovered too, since the witness accepts a root it already holds.
test('a registration that fails is pending: retried with the same root, by the button and on reload', { timeout: 180_000 }, async () => {
  const t = await open()
  const unavailable = /^Failed to load resource: the server responded with a status of 503/
  try {
    t.outage('down')
    await t.page.fill('#name', 'test')
    await t.page.click('#create-button')
    await t.page.waitForSelector('#pending:not([hidden])')
    await errorShown(t.page)
    const identity = await t.page.textContent('#identity-id')
    const rootText = await t.page.inputValue('#root-text')
    assert.deepEqual(await t.witnessGet(`/v1/identities/${identity}/records`), { ok: false, reason: 'unknown-identity' }, 'the witness does not have it')
    // Retried while still down: still pending.
    await t.page.click('#register-retry')
    await errorShown(t.page)
    assert.equal(await t.page.isHidden('#pending'), false)
    // The answer is lost: a reload retries by itself, with the same root; the witness takes it, and the page,
    // without the answer, still shows it pending.
    t.outage('lost')
    await t.collect()
    await t.page.reload()
    await errorShown(t.page)
    assert.equal(await t.page.isHidden('#pending'), false)
    const held = await t.witnessGet(`/v1/identities/${identity}/records`)
    assert.deepEqual(held.roots, [rootText], 'the witness has the root')
    // Back up: the retry button sends the same root again, which the witness already holds; the error is cleared.
    t.outage(null)
    await t.page.click('#register-retry')
    await t.page.waitForFunction(() => document.getElementById('status').textContent === 'Registered with the witness.')
    assert.equal(await t.page.textContent('#error'), '')
    assert.equal(await t.page.isHidden('#pending'), true)
    assert.equal(await t.page.textContent('#identity-id'), identity)
    assert.equal(await t.page.inputValue('#root-text'), rootText)
    // Registered: a reload does not register again, and nothing is pending.
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await t.page.isHidden('#pending'), true)
    assert.equal(await t.page.textContent('#status'), '')
    const credentials = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    assert.equal(credentials.credentials.length, 1, 'one passkey, never another')
    assert.deepEqual(t.problems.filter((p) => !unavailable.test(p)), [])
  } finally {
    await t.close()
  }
})

// A co-signature whose answer is lost is kept and sent again, as a registration is (#34): by the button and on
// reload, with the change gone from the page; the witness takes the same signature again.
test('a co-signature whose answer is lost is pending: sent again on reload and by the button', { timeout: 180_000 }, async () => {
  const t = await open()
  const unavailable = /^Failed to load resource: the server responded with a status of 503/
  try {
    const a = await createIdentity(t.page)
    const b = await t.device()
    await b.page.click('#join-button')
    await b.page.waitForSelector('#joining:not([hidden])')
    await t.page.fill('#new-root', await b.page.inputValue('#join-root'))
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    await t.page.click('#add-sign')
    await t.page.waitForSelector('#add-handoff:not([hidden])')
    await b.page.fill('#cosign-payload', await t.page.inputValue('#add-handoff'))
    await b.page.click('#cosign-review')
    await b.page.waitForSelector('#cosign-panel:not([hidden])')
    assert.equal(await b.page.isHidden('#cosign-pending'), true, 'nothing kept yet')
    // A passkey that refuses: reported, and nothing is kept or sent.
    await b.cdp.send('WebAuthn.setUserVerified', { authenticatorId: b.authenticatorId, isUserVerified: false })
    await b.page.click('#cosign-sign')
    await errorShown(b.page)
    assert.equal(await b.page.textContent('#error'), 'The passkey request was cancelled.')
    assert.equal(await b.page.isHidden('#cosign-pending'), true, 'nothing kept')
    assert.equal((await t.witnessGet(`/v1/identities/${a.identity}/records`)).memberships.length, 1, 'nothing sent')
    await b.cdp.send('WebAuthn.setUserVerified', { authenticatorId: b.authenticatorId, isUserVerified: true })
    t.outage('lost')
    await b.page.click('#cosign-sign')
    await errorShown(b.page)
    assert.equal(await b.page.isHidden('#cosign-pending'), false)
    assert.equal(await b.page.isHidden('#identity'), true, 'still joining')
    const signers = async () => (await t.witnessGet(`/v1/identities/${a.identity}/records`)).memberships.length
    assert.equal(await signers(), 2, 'the witness took it')
    // Reloaded, the change is no longer on the page; the kept co-signature is sent again, and its answer lost again.
    await t.collect()
    await b.page.reload()
    await errorShown(b.page)
    assert.equal(await b.page.inputValue('#cosign-payload'), '')
    assert.equal(await b.page.isHidden('#cosign-pending'), false)
    // Back up: the button sends it again; the witness already holds it, and this passkey is the identity's.
    t.outage(null)
    await b.page.click('#cosign-retry')
    await b.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await b.page.textContent('#identity-id'), a.identity)
    assert.equal(await b.page.textContent('#error'), '')
    assert.equal(await b.page.textContent('#status'), 'Co-signed. The change settles once its contest window has passed.')
    assert.equal(await signers(), 2, 'one signature each, never another')
    // Nothing is pending after a reload, and nothing is sent.
    await t.collect()
    await b.page.reload()
    await b.page.waitForSelector('#identity:not([hidden])')
    await b.page.waitForLoadState('networkidle')
    assert.deepEqual([await b.page.isHidden('#cosign-pending'), await b.page.isHidden('#joining'), await b.page.textContent('#status')], [true, true, ''])
    assert.deepEqual(t.problems.filter((p) => !unavailable.test(p)), [])
  } finally {
    await t.close()
  }
})

// Decision 3's batched renewal: the workers the page authorised are remembered, and one assertion renews up to eight.
const workerKey = (i) => Uint8Array.from({ length: 32 }, (_, j) => i + j)
const workerPub = (i) => hex(ed25519.getPublicKey(workerKey(i)))
const stored = (i, over = {}) => ({ agent: `w${i}`, subject: workerPub(i), aud: 'https://app.example', scopes: ['post'], lifetime: 3600, ...over })
const seed = (page, value) => page.evaluate((v) => localStorage.setItem('muid.workers', v), typeof value === 'string' ? value : JSON.stringify(value))
const kept = async (page) => JSON.parse(await page.evaluate(() => localStorage.getItem('muid.workers')))
const signCount = async (t) => (await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })).credentials[0].signCount

async function authoriseAndSign (page, fields) {
  await authorise(page, fields)
  await page.waitForSelector('#review-panel:not([hidden])')
  await page.click('#sign')
  await page.waitForSelector('#handoff:not([hidden])')
}

test('renewal: the workers authorised here are remembered, and one assertion renews them all, each accepted by the verifier', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const r = await createIdentity(t.page)
    const c = rootModule.checkRoot(r.text, { rpId })
    assert.equal(await t.page.isHidden('#renew'), true, 'nothing to renew yet')
    await authoriseAndSign(t.page, { agent: 'w1', subject: workerPub(1), scopes: 'read post', days: '1' })
    await authoriseAndSign(t.page, { agent: 'w2', subject: workerPub(2), scopes: 'post', days: '2' })
    await authoriseAndSign(t.page, { agent: 'w3', subject: workerPub(3), aud: 'https://other.example', scopes: 'score', days: '1' })
    // What was signed is remembered, with its lifetime; never a signature.
    const expected = [
      { agent: 'w1', subject: workerPub(1), aud: 'https://app.example', scopes: ['post', 'read'], lifetime: 86_400 },
      { agent: 'w2', subject: workerPub(2), aud: 'https://app.example', scopes: ['post'], lifetime: 172_800 },
      { agent: 'w3', subject: workerPub(3), aud: 'https://other.example', scopes: ['score'], lifetime: 86_400 },
    ]
    assert.deepEqual(await kept(t.page), expected)
    // Authorised again with other scopes, a worker replaces its older entry, last.
    await authoriseAndSign(t.page, { agent: 'w1', subject: workerPub(1), scopes: 'score post', days: '1' })
    expected.push({ ...expected.shift(), scopes: ['post', 'score'] })
    assert.deepEqual(await kept(t.page), expected)

    assert.equal(await t.page.isHidden('#renew'), false)
    const rows = await t.page.$$eval('#workers li', (lis) => lis.map((li) => ({ label: li.querySelector('label').textContent, key: li.querySelector('code').textContent,
      type: li.querySelector('input').getAttribute('type'), checked: li.querySelector('input').checked,
      button: li.querySelector('button').textContent, buttonType: li.querySelector('button').getAttribute('type') })))
    assert.deepEqual(rows, expected.map((w) => ({ label: ` ${w.agent} at ${w.aud}: ${w.scopes.join(' ')} ${w.subject}`, key: w.subject, type: 'checkbox', checked: true,
      button: 'Forget', buttonType: 'button' })))

    const before = await signCount(t)
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    assert.equal(await t.page.isHidden('#handoff'), true, 'a review withdraws what was handed over before')
    // I4: every delegation to be signed is shown, field by field.
    const shown = await t.page.$$eval('#renew-list > li', (lis) => lis.map((li) => [...li.querySelectorAll('dl > *')].map((e) => `${e.tagName}:${e.textContent}`)))
    assert.equal(shown.length, 3)
    for (const [i, w] of expected.entries()) {
      assert.deepEqual(shown[i].slice(0, 6), ['DT:Agent', `DD:${w.agent}`, 'DT:Audience', `DD:${w.aud}`, 'DT:Scopes', `DD:${w.scopes.join(' ')}`])
      assert.equal(shown[i][6], 'DT:Expires')
      assert.ok(Math.abs(Date.parse(shown[i][7].slice(3)) / 1000 - (Date.now() / 1000 + w.lifetime)) < 120, shown[i][7])
      assert.deepEqual(shown[i].slice(8), ['DT:Worker key', `DD:${w.subject}`])
    }
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    await t.page.click('#renew-sign')
    await t.page.waitForSelector('#renew-handoffs:not([hidden])')
    assert.equal(await signCount(t) - before, 1, 'one assertion')
    const areas = await t.page.$$eval('#renew-handoffs textarea', (ts) => ts.map((x) => ({ value: x.value, readOnly: x.readOnly, label: x.getAttribute('aria-label') })))
    assert.deepEqual(areas.map((a) => [a.readOnly, a.label]), expected.map((w) => [true, `Give this to ${w.agent}`]))
    const now = Math.floor(Date.now() / 1000)
    const { head } = await t.witnessGet(`/v1/identities/${r.identity}/head`)
    const ids = []
    for (const [i, w] of expected.entries()) {
      const h = JSON.parse(areas[i].value)
      const opened = envelope.open(envelope.wrap(h.payload, { root: h.root, subject: '0'.repeat(128) }), 'delegation')
      ids.push(opened.id)
      assert.deepEqual(JSON.parse(JSON.stringify(opened.body)), { agent: w.agent, identity: r.identity, membership: r.identity, root: c.id, subject: w.subject, aud: w.aud,
        scopes: w.scopes, nbf: opened.body.nbf, exp: opened.body.nbf + w.lifetime })
      assert.ok(Math.abs(opened.body.nbf - now) < 120)
      const secret = workerKey(Number(w.agent.slice(1)))
      const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(opened.id, 'hex')]), secret))
      const text = envelope.wrap(h.payload, { root: h.root, subject })
      const d = delegationModule.checkDelegation(text, { rootKey: c.key, rpId, origin: t.site.origin, now, skew: 60, maxLifetime: 2_592_000 })
      assert.equal(d.ok, true, JSON.stringify(d))
      const { logged } = await t.witnessPost('/v1/delegations', { identity: r.identity, text })
      const v = verifierModule.verifier({ rpId, origin: t.site.origin, audience: w.aud, witnessKeys: t.keys, skew: 60,
        maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
      const accepted = v.verifyDelegation({ delegation: text, root: r.text, head, logged }, { now, scope: w.scopes[0], revoked: [] })
      assert.equal(accepted.ok, true, JSON.stringify(accepted))
      assert.deepEqual(h.root.covers, JSON.parse(areas[0].value).root.covers, 'the one assertion, in every hand-off')
    }
    assert.deepEqual(JSON.parse(areas[0].value).root.covers, [...ids].sort(), 'it covers each delegation, sorted (W0)')
    assert.deepEqual(await kept(t.page), expected, 'a renewal changes nothing remembered')
    assert.deepEqual(t.problems, [])

    // Remembered on this browser: after a reload the workers are listed again.
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    assert.equal(await t.page.locator('#workers li').count(), 3)
  } finally {
    await t.close()
  }
})

// Issue #70: a new key authorised for an agent replaces the key remembered for it. The review says so before the
// passkey signs; afterwards only the new key is listed, renewed and stored, and a stored old key is not read back.
test('renewal: a new key for an agent retires its old one, said at the review; only the new key is renewed', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(1), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-retires'), '', 'nothing remembered: nothing replaced')
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    await authoriseAndSign(t.page, { agent: 'other', subject: workerPub(3), scopes: 'post' })
    // The same key again, here at another audience: nothing is replaced.
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(1), aud: 'https://other.example', scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-retires'), '', 'the same key')
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    assert.equal(await t.page.locator('#workers li').count(), 3)

    // A new key for the agent: the review names the key it replaces, and until it is signed nothing changes.
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-retires'), `This replaces the key remembered for forecaster, ${workerPub(1)}: that key will no longer be renewed here. ` +
      'It keeps working until what it was given expires, unless it is revoked.')
    assert.equal(await t.page.locator('#workers li').count(), 3)
    assert.equal((await kept(t.page)).length, 3)
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    const now = [{ agent: 'other', subject: workerPub(3), aud: 'https://app.example', scopes: ['post'], lifetime: 86_400 },
      { agent: 'forecaster', subject: workerPub(2), aud: 'https://app.example', scopes: ['post'], lifetime: 86_400 }]
    assert.deepEqual(await kept(t.page), now, 'the old key is gone, at both audiences')
    assert.deepEqual(await t.page.$$eval('#workers code', (cs) => cs.map((c) => c.textContent)), [workerPub(3), workerPub(2)])

    // Reviewed again once remembered, the new key replaces nothing: the notice is not left over.
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-retires'), '')

    // The renewal signs the new key and never the old.
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await t.page.click('#renew-sign')
    await t.page.waitForSelector('#renew-handoffs:not([hidden])')
    const handed = await t.page.$$eval('#renew-handoffs textarea', (ts) => ts.map((x) => x.value))
    const subjectOf = (h) => envelope.open(envelope.wrap(h.payload, { root: h.root, subject: '0'.repeat(128) }), 'delegation').body.subject
    assert.deepEqual(handed.map((h) => subjectOf(JSON.parse(h))), [workerPub(3), workerPub(2)])

    // An old key written back into storage (another tab of an older page, or anything on the origin) is not read back.
    await seed(t.page, [{ ...now[1], subject: workerPub(1) }, ...now])
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    assert.deepEqual(await t.page.$$eval('#workers code', (cs) => cs.map((c) => c.textContent)), [workerPub(3), workerPub(2)])
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('renewal, I4: 1 to 8 at once; a change of selection withdraws; a forgotten worker is gone; stored workers are untrusted', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    // Before there is an identity, remembered workers are not offered.
    await seed(t.page, Array.from({ length: 9 }, (_, i) => stored(i + 1)))
    await t.page.reload()
    await t.page.waitForSelector('#create:not([hidden])')
    assert.equal(await t.page.isHidden('#renew'), true)
    await createIdentity(t.page)
    assert.equal(await t.page.isHidden('#renew'), false)
    assert.equal(await t.page.locator('#workers li').count(), 9)
    await t.page.evaluate(() => document.getElementById('renew-sign').click())
    assert.equal(await t.page.isHidden('#renew-handoffs'), true, 'nothing is signed without a review')
    await t.page.click('#renew-review')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'renew 1 to 8 workers at once')
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    // Without the third, eight are reviewed: the others, in order.
    await t.page.locator('#workers input').nth(2).uncheck()
    assert.equal(await t.page.textContent('#error'), '', 'a change of selection clears the refusal')
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    const agents = () => t.page.$$eval('#renew-list > li', (lis) => lis.map((li) => li.querySelector('dd').textContent))
    assert.deepEqual(await agents(), ['w1', 'w2', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9'])
    await t.page.locator('#workers input').nth(0).uncheck()
    assert.equal(await t.page.isHidden('#renew-panel'), true, 'a change of selection withdraws the review')
    await t.page.evaluate(() => document.getElementById('renew-sign').click())
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    assert.equal(await t.page.textContent('#error'), '')
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    assert.deepEqual(await agents(), ['w2', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9'])
    // Signed and handed over; any later change of selection withdraws the hand-offs too.
    await t.page.click('#renew-sign')
    await t.page.waitForSelector('#renew-handoffs:not([hidden])')
    assert.equal(await t.page.locator('#renew-handoffs textarea').count(), 7)
    await t.page.locator('#workers input').nth(0).check()
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    // Forgetting a worker withdraws a review, removes it from the list and from what is kept; the rest stay.
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await t.page.locator('#workers button').nth(1).click()
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    assert.deepEqual((await kept(t.page)).map((w) => w.agent), ['w1', 'w3', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9'])
    assert.equal(await t.page.locator('#workers li').count(), 8)
    assert.equal(await t.page.locator('#workers input:checked').count(), 8)
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    assert.deepEqual(await agents(), ['w1', 'w3', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9'])
    // None ticked: refused.
    for (let i = 0; i < 8; i++) await t.page.locator('#workers input').nth(i).uncheck()
    await t.page.click('#renew-review')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'renew 1 to 8 workers at once')
    // One agent at two audiences is two entries, and so are two agents with one key: forgetting one keeps the others.
    await seed(t.page, [stored(1), stored(1, { aud: 'https://other.example' }), stored(1, { agent: 'w5' })])
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    assert.equal(await t.page.locator('#workers li').count(), 3)
    await t.page.locator('#workers button').nth(0).click()
    assert.deepEqual(await kept(t.page), [stored(1, { aud: 'https://other.example' }), stored(1, { agent: 'w5' })])
    // The last one forgotten, there is nothing to renew.
    await t.page.locator('#workers button').nth(0).click()
    await t.page.locator('#workers button').nth(0).click()
    assert.deepEqual(await kept(t.page), [])
    assert.equal(await t.page.isHidden('#renew'), true)

    // Stored state is untrusted: entries not of a worker's form are dropped, and one of the form gets every check a
    // new delegation gets, shown as text.
    await seed(t.page, [stored(1), { agent: 'x' }, 7, stored(2, { aud: 'https://App.example', agent: '<b>bold</b>' })])
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    assert.equal(await t.page.locator('#workers li').count(), 2)
    assert.equal(await t.page.locator('#workers b').count(), 0)
    assert.match(await t.page.locator('#workers label').nth(1).textContent(), /^ <b>bold<\/b> at /)
    await t.page.click('#renew-review')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), "the agent's name must be a lower-case name, such as forecaster")
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    // Unreadable, or not a list: nothing to renew.
    for (const junk of ['{', '{"length":1}', 'null']) {
      await seed(t.page, junk)
      await t.collect()
      await t.page.reload()
      await t.page.waitForSelector('#identity:not([hidden])')
      assert.equal(await t.page.isHidden('#renew'), true, junk)
    }
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('renewal: a change of selection while the passkey is signing withdraws it: the late signature is not handed over', { timeout: 120_000 }, async () => {
  const t = await open({ init: () => {
    const get = navigator.credentials.get.bind(navigator.credentials)
    navigator.credentials.get = async (o) => {
      await new Promise((resolve) => setTimeout(resolve, 500))
      if (globalThis.refusing) throw new DOMException('refused', 'NotAllowedError')
      return get(o)
    }
  } })
  try {
    await seed(t.page, [stored(1), stored(2)])
    await t.page.reload()
    await createIdentity(t.page)
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await t.page.click('#renew-sign')
    await t.page.locator('#workers input').nth(1).uncheck()
    await t.page.waitForTimeout(1500)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    assert.equal(await t.page.locator('#renew-handoffs textarea').count(), 0)
    // A passkey that refuses is reported, and nothing is handed over; signing again clears it.
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await t.page.evaluate(() => { globalThis.refusing = true })
    await t.page.click('#renew-sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'The passkey request was cancelled.')
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    await t.page.evaluate(() => { globalThis.refusing = false })
    await t.page.click('#renew-sign')
    await t.page.waitForSelector('#renew-handoffs:not([hidden])')
    assert.equal(await t.page.textContent('#error'), '')
    assert.equal(await t.page.locator('#renew-handoffs textarea').count(), 1)
  } finally {
    await t.close()
  }
})

test('renewal: a worker another tab remembers or forgets is followed here; a joining passkey renews nothing', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    const other = await t.tab(t.context)
    await other.waitForSelector('#identity:not([hidden])')
    assert.equal(await other.isHidden('#renew'), true)
    await authoriseAndSign(t.page, { agent: 'w1', subject: workerPub(1) })
    await other.waitForSelector('#renew:not([hidden])')
    assert.equal(await other.locator('#workers li').count(), 1)
    // A review open in the first tab is withdrawn when the other tab forgets the worker.
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await other.locator('#workers button').nth(0).click()
    await t.page.waitForSelector('#renew', { state: 'hidden' })
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    assert.equal(await t.page.locator('#workers li').count(), 0)
    // A passkey still joining another identity has no authority to renew with: remembered workers are not offered.
    const d = await t.device()
    await seed(d.page, [stored(1)])
    await d.page.click('#join-button')
    await d.page.waitForSelector('#joining:not([hidden])')
    assert.equal(await d.page.isHidden('#renew'), true)
    await d.page.reload()
    await d.page.waitForSelector('#joining:not([hidden])')
    assert.equal(await d.page.isHidden('#renew'), true)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})
