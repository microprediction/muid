// The id page in Chrome, with a virtual authenticator (Chrome DevTools Protocol, WebAuthn domain): an identity is
// created, a worker authorised by one assertion, and what the page hands the worker, once the worker consents,
// verifies under the core — through the witness's head and the relying party's verifier.
import { test as nodeTest, after } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { chromium } from 'playwright-core'
import { generateKeyPairSync, createPrivateKey, createHash } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { records as pageRecords } from './impl.mjs'
import { make as makeAssertion, authData, clientData, challengeFor } from '../assertion/helpers.mjs'
import { membership as membershipModule } from '../impl.mjs'
import { root as rootModule, delegation as delegationModule, assertion as assertionModule, envelope, verifier as verifierModule } from '../impl.mjs'
import { witness, witnessService, memoryHoldings, memoryLog } from '../witness/impl.mjs'
import { serve } from './serve.mjs'
import { activate, handBack } from './mutant.mjs'
import fc from 'fast-check'
import { runs } from '../runs.mjs'

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
  const closed = Promise.all([...opened].map((end) => end())).then(async () => { if (shared !== undefined) await (await shared).close() })
  if (await Promise.race([closed, late]) === 'late') throw new Error(`${opened.size} browser(s) still open ${CLOSE_WITHIN / 1000}s after the last test`)
})

// One browser for the file: each test's devices are contexts of it, each with its own storage and authenticator,
// closed when the test ends. Launching one for every test was most of what a test cost.
let shared
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
  shared ??= chromium.launch({ channel: 'chrome', headless: true })
  const browser = await shared
  const contexts = []
  const end = async () => { opened.delete(end); await Promise.all(contexts.map((c) => c.close())); site.close() }
  opened.add(end)
  const problems = []
  const pages = []
  // Chrome warns that only ES256 is offered: deliberate (I6), and the only warning allowed.
  const ES256_ONLY = /^publicKey\.pubKeyCredParams is missing at least one of the default algorithm identifiers: ES256 and RS256\./
  function watched (page) {
    page.on('console', (m) => { if ((m.type() === 'error' || m.type() === 'warning') && !ES256_ONLY.test(m.text())) problems.push(m.text()) })
    page.on('pageerror', (e) => problems.push(String(e)))
    flying.set(page, 0)
    page.on('request', () => flying.set(page, flying.get(page) + 1))
    for (const over of ['requestfinished', 'requestfailed']) page.on(over, () => flying.set(page, flying.get(page) - 1))
    // A reload begins the page again, and with it the count of what it ran: that is handed back first. So it is
    // before the test sends the page elsewhere.
    const reload = page.reload.bind(page)
    page.reload = async (...options) => { await handBack([page]); return reload(...options) }
    const goto = page.goto.bind(page)
    page.goto = async (...to) => { await handBack([page]); return goto(...to) }
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
    contexts.push(context)
    if (FAIL_FAST) context.setDefaultTimeout(WAIT)
    await activate(context)
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
  const collect = () => handBack(pages)
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
  // `gate()`: the witness answers nothing until the function it returns is called; then it is itself again.
  const gate = () => {
    let release
    const waiting = new Promise((resolve) => { release = resolve })
    holder.svc = { handle: async (r) => { await waiting; return real.handle(r) } }
    return () => { holder.svc = real; release() }
  }
  return { site, browser, ...first, device, tab, problems, collect, keys, clock, witnessGet, witnessPost, svc: real, refusing, outage, gate, advance: (s) => { offset += s },
    close: async () => { await collect(); await end() } }
}

// The page's store (SPEC §7) read and written directly: IndexedDB, with no notice to any tab, as a tab not yet told
// of a change finds it. `held` gives a key's value (null if absent); `hold` sets it; `drop` removes it.
const direct = (page, mode, key, value) => page.evaluate(([mode, key, value]) => new Promise((resolve, reject) => {
  const opening = indexedDB.open('muid', 1)
  opening.onupgradeneeded = () => opening.result.createObjectStore('values')
  opening.onerror = () => reject(opening.error)
  opening.onsuccess = () => {
    const tx = opening.result.transaction('values', mode === 'get' ? 'readonly' : 'readwrite')
    const values = tx.objectStore('values')
    let out = null
    if (mode === 'get' || mode === 'wait') values.get(key).onsuccess = (e) => { if (e.target.result !== undefined) out = e.target.result.value }
    else if (mode === 'delete') values.delete(key)
    else values.put({ value }, key)
    tx.oncomplete = () => { opening.result.close(); resolve(out) }
    tx.onabort = () => reject(tx.error)
  }
}), [mode, key, value])
const held = (page, key) => direct(page, 'get', key)
// Each page's requests not yet answered, counted from when it was opened.
const flying = new WeakMap()
// The page has nothing on its way, for a check that something did not happen: no request unanswered, and the page's
// tasks and every write its store had queued run since (a writing transaction that changes nothing ends after them).
// Seen so twice running, since an answer may begin a write and a write a request. Playwright's wait for the load
// state 'networkidle' is no such wait: a loaded page reached that state long ago, and it returns at once.
async function idle (page) {
  for (let quiet = 0; quiet < 2;) {
    await direct(page, 'wait', 'root')
    await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 0)))
    quiet = flying.get(page) === 0 ? quiet + 1 : 0
    if (quiet === 0) await page.waitForTimeout(20)
  }
}
const hold = (page, key, value) => direct(page, 'put', key, value)
const drop = (page, key) => direct(page, 'delete', key)
// A change made through the adapter from this page, as any page of the origin makes one: every tab's page is told.
const change = (page, key, value) => page.evaluate(async ([key, value]) => {
  const { openStore } = await import('/id/store.js')
  const s = await openStore('muid')
  await s.update(key, () => value === null ? { absent: true } : { value })
  s.close()
}, [key, value])
// A tab holds a read-write transaction open on the store, so every other operation on it waits, until freed.
const holdStoreIn = (page) => page.evaluate(() => new Promise((resolve, reject) => {
  const opening = indexedDB.open('muid', 1)
  opening.onerror = () => reject(opening.error)
  opening.onsuccess = () => {
    const tx = opening.result.transaction('values', 'readwrite')
    const values = tx.objectStore('values')
    globalThis.holding = true
    globalThis.freed = new Promise((resolve) => { tx.oncomplete = () => { opening.result.close(); resolve() } })
    const spin = () => { if (globalThis.holding) values.get('workers').onsuccess = spin }
    spin()
    resolve()
  }
}))
const freeStoreIn = (page) => page.evaluate(() => { globalThis.holding = false; return globalThis.freed })
// Tells every tab's page that a key changed, whether or not it did.
const tell = (page, key) => page.evaluate((key) => { const c = new BroadcastChannel('muid-store:muid'); c.postMessage(key); c.close() }, key)

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
    assert.equal((await held(t.page, 'root')).text, r.text)

    // Surrounding spaces are not part of what is signed.
    await authorise(t.page, { agent: ' forecaster ', subject: ` ${SUBJECT} `, aud: ' https://app.example ', scopes: ' post  read ' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-agent'), 'forecaster')
    assert.equal(await t.page.textContent('#show-aud'), 'https://app.example')
    assert.equal(await t.page.textContent('#show-scopes'), 'post read')
    assert.equal(await t.page.textContent('#show-subject'), SUBJECT)
    const exp = Date.parse(await t.page.textContent('#show-exp')) / 1000
    assert.ok(Math.abs(exp - (Date.now() / 1000 + 86_400)) < 120)
    assert.equal(await t.page.isHidden('#handoff-copy'), true, 'nothing to copy before anything is handed over')
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    const h = JSON.parse(await t.page.inputValue('#handoff'))
    // The Copy button puts exactly the line shown on the clipboard, and says so; a clipboard that refuses is said.
    await t.context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await t.page.click('#handoff-copy')
    await t.page.waitForFunction(() => document.getElementById('status').textContent === 'Copied.')
    assert.equal(await t.page.evaluate(() => navigator.clipboard.readText()), await t.page.inputValue('#handoff'))
    await t.page.evaluate(() => { navigator.clipboard.writeText = async () => { throw new Error('the clipboard refused') } })
    await t.page.click('#handoff-copy')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'the clipboard refused')
    // Reviewing again withdraws what was handed over until it is signed again, and the button with it.
    await t.page.click('#review')
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.equal(await t.page.isHidden('#handoff-copy'), true)

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
    assert.equal(await kept(t.page), null, 'nor is the worker remembered (a surviving mutant)')
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
    const own = (await held(t.page, 'root')).credential
    assert.deepEqual(await t.page.evaluate(() => globalThis.asked), [['public-key', Buffer.from(own, 'base64url').toString('base64')]])
    const key = rootModule.checkRoot(r.text, { rpId: 'localhost' }).key
    const id = h.root.covers[0]
    assert.deepEqual({ ...assertionModule.checkRootAssertion(h.root, { record: id, rpId: 'localhost', origin: t.site.origin, key }) }, { ok: true })
  } finally {
    await t.close()
  }
})

test('an unreadable stored identity is forgotten: the page offers to create one', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    await t.page.waitForSelector('#create:not([hidden])')
    for (const unreadable of ['{', 7, [], { identity: 'x' }]) {
      await hold(t.page, 'root', unreadable)
      await t.collect()
      await t.page.reload()
      await t.page.waitForSelector('#create:not([hidden])')
    }
    await t.page.waitForSelector('#create:not([hidden])')
    assert.equal(await t.page.isHidden('#identity'), true)
    assert.equal(await t.page.isHidden('#authorise'), true)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('a stored root of the wrong form is forgotten, not shown; what is stored for the workers and is no list of them is none', { timeout: 120_000 }, async () => {
  const t = await open()
  try {
    await t.page.waitForSelector('#create:not([hidden])')
    await hold(t.page, 'root', { identity: '<b>x</b>', text: 5 })
    await hold(t.page, 'workers', null)
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#create:not([hidden])')
    assert.equal(await t.page.isHidden('#identity'), true)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// SPEC §7: the page keeps what it keeps through its storage adapter. Without storage it offers nothing, and says so.
test('a browser that gives the page no storage is told so, and offered nothing', { timeout: 120_000 }, async () => {
  const t = await open({ init: () => { IDBFactory.prototype.open = () => { throw new DOMException('no', 'SecurityError') } } })
  try {
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'This browser gave the page no storage: it can do nothing here.')
    for (const id of ['create', 'identity', 'authorise', 'renew', 'add-root', 'joining']) assert.equal(await t.page.isHidden('#' + id), true, id)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Two versions of the page in one browser (model/STATE.md): a page of a later version raises the database's version,
// and this one's store is closed (the standard's `versionchange`). It then offers nothing, whatever it had open, and
// says to reload; the same code loaded again is refused the raised database, so it never writes a later form's data.
test('a page whose storage a newer version of the page has taken withdraws what is open, offers nothing and says so', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    // A signature asked for before the loss and given after it: nothing can be kept, and the page still says why.
    await t.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve })
      navigator.credentials.get = async (o) => { const c = await get(o); globalThis.asking(); await new Promise((resolve) => { globalThis.answer = resolve }); return c }
    })
    await t.page.click('#sign')
    await t.page.evaluate(() => globalThis.asked)
    const raised = await t.page.evaluate(() => new Promise((resolve) => {
      const o = indexedDB.open('muid', 2)
      o.onblocked = () => resolve('blocked')
      o.onsuccess = () => { o.result.close(); resolve('raised') }
    }))
    assert.equal(raised, 'raised')
    await t.page.waitForFunction(() => document.getElementById('error').textContent !== '')
    assert.equal(await t.page.textContent('#error'), 'A newer version of this page has taken its storage, or the browser has cleared it: reload this page.')
    const offered = async () => { for (const id of ['create', 'identity', 'authorise', 'renew', 'add-root', 'joining', 'pending', 'review-panel', 'handoff']) assert.equal(await t.page.isHidden('#' + id), true, id) }
    await offered()
    await t.page.evaluate(() => globalThis.answer())
    await t.page.waitForTimeout(500)
    assert.equal(await t.page.textContent('#error'), 'A newer version of this page has taken its storage, or the browser has cleared it: reload this page.')
    await offered()
    await t.collect()
    await t.page.reload()
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'This browser gave the page no storage: it can do nothing here.')
    for (const id of ['create', 'identity', 'authorise']) assert.equal(await t.page.isHidden('#' + id), true, id)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// A root is stored only while storage holds the root this tab acts for (none, when it creates one): the write and
// that check are one transaction, so two tabs creating at once keep one identity, and neither writes over the other.
test('a root another tab stored while this one was creating its own is adopted, not overwritten; nor by a later registration', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    // Another device's root, of the right form for this site, stands for what another tab stores meanwhile.
    const d = await t.device()
    const theirs = await createIdentity(d.page)
    const stored = await held(d.page, 'root')
    await t.page.evaluate(() => {
      const create = navigator.credentials.create.bind(navigator.credentials)
      globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve })
      navigator.credentials.create = async (o) => { const c = await create(o); globalThis.asking(); await new Promise((resolve) => { globalThis.answer = resolve }); return c }
    })
    await t.page.bringToFront()
    await t.page.fill('#name', 'mine')
    await t.page.click('#create-button')
    await t.page.evaluate(() => globalThis.asked)
    await hold(t.page, 'root', stored)
    await t.page.evaluate(() => globalThis.answer())
    await t.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await t.page.textContent('#identity-id'), theirs.identity, 'the stored identity is the one shown')
    assert.deepEqual(await held(t.page, 'root'), stored, 'and it was not written over')
    // A registration that completes after the stored root has become another's marks nothing on it.
    const fresh = await open()
    try {
      await fresh.page.route('**/v1/records', async (route) => { await hold(fresh.page, 'root', { ...stored, registered: false }); await route.continue() })
      await fresh.page.fill('#name', 'second')
      await fresh.page.click('#create-button')
      await fresh.page.waitForFunction((id) => document.getElementById('identity-id').textContent === id, theirs.identity)
      assert.deepEqual(await held(fresh.page, 'root'), { ...stored, registered: false }, 'not marked registered by another root\'s registration')
    } finally {
      await fresh.close()
    }
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Found by review (#74): what a tab does after a root is stored follows the root that was stored, not what the tab
// set out to do. A Create that loses to another tab's Join registers nothing; a registration, or a co-signature,
// marks only the root it was made for.
test('a Create that adopts another tab\'s joining root registers nothing; a registration marks only its own root, though the tab was told of another', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const d = await t.device()
    const theirs = await createIdentity(d.page)
    const stored = await held(d.page, 'root')
    const joiner = { ...stored, joining: true, registered: false }
    const posted = []
    await t.page.route('**/v1/records', async (route) => { posted.push(route.request().postDataJSON()); await route.continue() })
    await t.page.evaluate(() => {
      const create = navigator.credentials.create.bind(navigator.credentials)
      globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve })
      navigator.credentials.create = async (o) => { const c = await create(o); globalThis.asking(); await new Promise((resolve) => { globalThis.answer = resolve }); return c }
    })
    await t.page.bringToFront()
    await t.page.fill('#name', 'mine')
    await t.page.click('#create-button')
    await t.page.evaluate(() => globalThis.asked)
    await hold(t.page, 'root', joiner)
    await t.page.evaluate(() => globalThis.answer())
    await t.page.waitForSelector('#joining:not([hidden])')
    await idle(t.page)
    assert.deepEqual(posted, [], 'the joining root is sent to no witness')
    assert.deepEqual(await held(t.page, 'root'), joiner, 'and is kept as it was')
    assert.equal(await t.page.textContent('#status'), '')
    // A registration under way when the stored root becomes another's, and this tab is told: the other is not marked.
    const fresh = await open()
    try {
      const other = { ...stored, registered: false }
      await fresh.page.route('**/v1/records', async (route) => {
        await change(fresh.page, 'root', other)
        await fresh.page.waitForFunction((id) => document.getElementById('identity-id').textContent === id, theirs.identity)
        await route.continue()
      })
      await fresh.page.fill('#name', 'second')
      await fresh.page.click('#create-button')
      await fresh.page.waitForFunction((id) => document.getElementById('identity-id').textContent === id, theirs.identity)
      await idle(fresh.page)
      assert.deepEqual(await held(fresh.page, 'root'), other, 'not marked registered by another root\'s registration')
      assert.equal(await fresh.page.textContent('#status'), '', 'nor said to be')
    } finally {
      await fresh.close()
    }
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
    // While the registration is on its way the other tab, told of the root, asks the witness nothing about an
    // identity it does not yet hold; once it is registered, it asks (R11: a recovery under notice).
    const asks = []
    other.on('request', (r) => { if (r.method() === 'GET' && /\/records$/.test(r.url())) asks.push(r.url()) })
    const release = t.gate()
    await t.page.fill('#name', 'test')
    await t.page.click('#create-button')
    await other.waitForSelector('#identity:not([hidden])')
    await other.waitForTimeout(500)
    assert.deepEqual(asks, [])
    release()
    await t.page.waitForFunction(() => document.getElementById('status').textContent === 'Registered with the witness.')
    const a = { text: await t.page.inputValue('#root-text'), identity: await t.page.textContent('#identity-id') }
    for (let i = 0; asks.length === 0 && i < 50; i++) await other.waitForTimeout(100)
    assert.deepEqual(asks, [`${t.site.origin}/witness/v1/identities/${a.identity}/records`])
    await idle(other)
    // The other tab, open since before, now shows the identity and offers no create.
    await other.waitForSelector('#identity:not([hidden])')
    assert.equal(await other.textContent('#identity-id'), a.identity)
    assert.equal(await other.isHidden('#create'), true)
    // A create begun in a tab that has not yet heard of it adopts the stored identity and creates nothing.
    const stored = await held(other, 'root')
    await drop(other, 'root')
    await tell(t.page, 'root')
    await other.waitForSelector('#create:not([hidden])')
    await hold(other, 'root', stored)
    await other.click('#create-button')
    await other.waitForSelector('#identity:not([hidden])')
    assert.equal(await other.textContent('#identity-id'), a.identity)
    assert.equal((await held(t.page, 'root')).identity, a.identity, 'not overwritten')
    // A review open in the other tab is withdrawn when what is stored changes; storage cleared there is followed too.
    await other.fill('#agent', 'forecaster')
    await other.fill('#subject', SUBJECT)
    await other.fill('#aud', 'https://app.example')
    await other.fill('#scopes', 'post')
    await other.click('#review')
    await other.waitForSelector('#review-panel:not([hidden])')
    await change(t.page, 'root', { ...stored, note: 1 })
    await other.waitForSelector('#review-panel', { state: 'hidden' })
    await change(t.page, 'root', null)
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
    await idle(outer)
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
    await idle(b.page)
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
    assert.equal(await t.page.textContent('#add-recovery'), 'none')
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
    assert.equal(await b.page.textContent('#cosign-recovery'), 'none')
    await b.page.click('#cosign-sign')
    await b.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await b.page.textContent('#identity-id'), a.identity)
    // Co-signed, it is part of the identity: nothing is pending, and a reload registers nothing.
    await t.collect()
    await b.page.reload()
    await b.page.waitForSelector('#identity:not([hidden])')
    await idle(b.page)
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

test('a co-signature is kept, and its root made the identity\'s, only for the root that signed it', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    const b = await t.device()
    await b.page.click('#join-button')
    await b.page.waitForSelector('#joining:not([hidden])')
    const mine = await held(b.page, 'root')
    // Another joining root, of the right form for this site, stands for what the browser holds instead meanwhile.
    const c = await t.device()
    await c.page.click('#join-button')
    await c.page.waitForSelector('#joining:not([hidden])')
    const other = await held(c.page, 'root')
    await t.page.bringToFront()
    await t.page.fill('#new-root', await b.page.inputValue('#join-root'))
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    await t.page.click('#add-sign')
    await t.page.waitForSelector('#add-handoff:not([hidden])')
    const payload = await t.page.inputValue('#add-handoff')
    const posted = []
    let swap = false
    await b.page.route('**/v1/records', async (route) => {
      posted.push(route.request().postDataJSON().type)
      if (swap) {
        await change(b.page, 'root', other)
        await b.page.waitForFunction((text) => document.getElementById('join-root').value === text, other.text)
        // From here the page's next write to its store is the one that follows the witness's answer.
        await b.page.evaluate(() => { globalThis.from = globalThis.begun })
      }
      await route.continue()
    })
    const review = async () => {
      await b.page.bringToFront()
      await b.page.fill('#cosign-payload', payload)
      await b.page.click('#cosign-review')
      await b.page.waitForSelector('#cosign-panel:not([hidden])')
    }
    // The stored root becomes another while the passkey is asked: the co-signature is not kept, and not sent.
    await b.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve })
      navigator.credentials.get = async (o) => { const a = await get(o); navigator.credentials.get = get; globalThis.asking(); await new Promise((resolve) => { globalThis.answer = resolve }); return a }
    })
    await review()
    await b.page.click('#cosign-sign')
    await b.page.evaluate(() => globalThis.asked)
    await hold(b.page, 'root', other)
    await b.page.evaluate(() => globalThis.answer())
    await b.page.waitForFunction((text) => document.getElementById('join-root').value === text, other.text)
    await idle(b.page)
    assert.deepEqual(posted, [], 'nothing is sent')
    assert.equal(await b.page.textContent('#error'), '', 'and nothing is tried')
    assert.deepEqual(await held(b.page, 'root'), other, 'and the root there is left as it was')
    // It becomes another while the witness is asked, and the tab is told: the other root is not marked.
    await change(b.page, 'root', mine)
    await b.page.waitForFunction((text) => document.getElementById('join-root').value === text, mine.text)
    await review()
    swap = true
    // The page's writes to its store are counted as they begin and noted as they end, so that the one after the
    // witness's answer is waited for: until then a page that marks the wrong root has not yet done so.
    await b.page.evaluate(() => {
      globalThis.begun = 0
      globalThis.ended = -1
      const transaction = IDBDatabase.prototype.transaction
      IDBDatabase.prototype.transaction = function (names, mode, options) {
        const tx = transaction.call(this, names, mode, options)
        if (mode !== 'readwrite') return tx
        const n = globalThis.begun++
        for (const e of ['complete', 'abort']) tx.addEventListener(e, () => { globalThis.ended = Math.max(globalThis.ended, n) })
        return tx
      }
    })
    await b.page.click('#cosign-sign')
    await b.page.waitForFunction(() => globalThis.from !== undefined && globalThis.ended >= globalThis.from)
    assert.equal(await b.page.inputValue('#join-root'), other.text)
    assert.deepEqual(posted, ['membership'])
    assert.deepEqual(await held(b.page, 'root'), other, 'the other root is not made the identity\'s')
    assert.equal(await b.page.textContent('#status'), '', 'nor said to be co-signed')
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
    assert.equal(await t.page.isHidden('#notice-unchecked'), true, 'a root not yet registered is not asked about, and nothing is said of that')
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
    await idle(b.page)
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
// What is stored for the workers is { rev, workers }: `seed` writes a list as one more change; `kept` reads the list.
const seed = async (page, value) => hold(page, 'workers', { rev: ((await held(page, 'workers'))?.rev ?? 0) + 1, workers: value })
const kept = async (page) => (await held(page, 'workers'))?.workers ?? null
const signCount = async (t) => (await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })).credentials[0].signCount

// Forget pressed on the nth remembered worker, and the change made (the list is one shorter) or refused (an error).
async function forget (page, n) {
  const listed = await page.locator('#workers li').count()
  await page.locator('#workers button').nth(n).click()
  await page.waitForFunction((listed) => document.querySelectorAll('#workers li').length !== listed || document.getElementById('error').textContent !== '', listed)
}

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
    // Each hand-off has its own Copy button, after it, which copies that one and no other; a failure clears on the next.
    assert.deepEqual(await t.page.$$eval('#renew-handoffs > *', (xs) => xs.map((x) => [x.tagName, x.className, x.type, x.tagName === 'BUTTON' ? x.textContent : ''])),
      areas.flatMap(() => [['TEXTAREA', '', 'textarea', ''], ['BUTTON', 'copy', 'button', 'Copy']]))
    await t.context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await t.page.evaluate(() => { document.getElementById('error').textContent = 'an earlier error' })
    for (let i = areas.length - 1; i >= 0; i--) {
      await t.page.evaluate(() => { document.getElementById('status').textContent = '' })
      await t.page.locator('#renew-handoffs button.copy').nth(i).click()
      await t.page.waitForFunction(() => document.getElementById('status').textContent === 'Copied.')
      assert.equal(await t.page.evaluate(() => navigator.clipboard.readText()), areas[i].value)
      assert.equal(await t.page.textContent('#error'), '')
    }
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
    await forget(t.page, 1)
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    assert.deepEqual((await kept(t.page)).map((w) => w.agent), ['w1', 'w3', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9'])
    assert.equal(await t.page.locator('#workers li').count(), 8)
    // The list is drawn again: what was unticked (the third, now second) stays unticked.
    assert.deepEqual(await t.page.$$eval('#workers input', (bs) => bs.map((b) => b.checked)), [true, false, true, true, true, true, true, true])
    await t.page.locator('#workers input').nth(1).check()
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
    await forget(t.page, 0)
    assert.deepEqual(await kept(t.page), [stored(1, { aud: 'https://other.example' }), stored(1, { agent: 'w5' })])
    // The last one forgotten, there is nothing to renew.
    await forget(t.page, 0)
    await forget(t.page, 0)
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

// Found by review: a review waits for the witness (the current membership) before it shows anything. Whatever
// withdraws a review withdraws one that is still waiting: it shows nothing when the answer comes, and signs nothing.
test('a change made while a review waits for the witness withdraws it: of one worker, and of a renewal', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    await authoriseAndSign(t.page, { agent: 'w1', subject: workerPub(1), scopes: 'post' })
    await authoriseAndSign(t.page, { agent: 'w2', subject: workerPub(2), scopes: 'post' })
    const other = await t.tab(t.context)
    await other.waitForSelector('#renew:not([hidden])')
    // The witness's answer to the page's question is held until released.
    let release
    let asked
    const hold = () => {
      const seen = new Promise((resolve) => { asked = resolve })
      const gate = new Promise((resolve) => { release = resolve })
      return { seen, gate }
    }
    let held = null
    await t.page.route('**/v1/identities/*/records', async (route) => {
      if (held !== null) { asked(); await held.gate }
      await route.continue()
    })
    const settled = async () => { release(); held = null; await idle(t.page); await t.page.waitForTimeout(300) }
    const before = await signCount(t)

    // One worker: a field edited while the witness is asked.
    held = hold()
    await authorise(t.page, { agent: 'w3', subject: workerPub(3), scopes: 'post' })
    await held.seen
    await t.page.fill('#scopes', 'admin')
    await settled()
    assert.equal(await t.page.isHidden('#review-panel'), true, 'the edited review is not shown')
    await t.page.evaluate(() => document.getElementById('sign').click())
    // Read before the question, the fields signed are those reviewed: reviewed again, unedited, it is what is shown.
    held = hold()
    await authorise(t.page, { agent: 'w3', subject: workerPub(3), scopes: 'post' })
    await held.seen
    await settled()
    assert.equal(await t.page.isHidden('#review-panel'), false)
    assert.equal(await t.page.textContent('#show-scopes'), 'post')

    // A renewal: a box unticked while the witness is asked.
    held = hold()
    await t.page.click('#renew-review')
    await held.seen
    await t.page.locator('#workers input').nth(0).uncheck()
    await settled()
    assert.equal(await t.page.isHidden('#renew-panel'), true, 'the changed selection is not shown')
    await t.page.evaluate(() => document.getElementById('renew-sign').click())
    // A renewal: another tab forgets a worker while the witness is asked.
    await t.page.locator('#workers input').nth(0).check()
    held = hold()
    await t.page.click('#renew-review')
    await held.seen
    await forget(other, 0)
    await t.page.waitForFunction(() => document.querySelectorAll('#workers li').length === 1)
    await settled()
    assert.equal(await t.page.isHidden('#renew-panel'), true, 'the forgotten worker is not shown for renewal')
    await t.page.evaluate(() => document.getElementById('renew-sign').click())
    await t.page.waitForTimeout(500)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.equal(await signCount(t), before, 'nothing was signed')
    // Unchanged while the witness is asked, a renewal is shown.
    held = hold()
    await t.page.click('#renew-review')
    await held.seen
    await settled()
    assert.equal(await t.page.isHidden('#renew-panel'), false)
    assert.deepEqual(await t.page.$$eval('#renew-list > li', (lis) => lis.map((li) => li.querySelector('dd').textContent)), ['w2'])
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Found by review of #71. Each tab drew its list from storage once and wrote the whole list back, so a tab not yet told
// of another's change undid it. A change is now made to what storage holds at that moment, and a review made before
// another tab's change is not signed. Storage notifications to a tab are held here to make it that late tab.
const HOLD_STORAGE = () => {
  const add = BroadcastChannel.prototype.addEventListener
  globalThis.heldStorage = []
  globalThis.holdStorage = false
  BroadcastChannel.prototype.addEventListener = function (type, fn, ...rest) {
    return add.call(this, type, (e) => { if (globalThis.holdStorage) globalThis.heldStorage.push(() => fn(e)); else fn(e) }, ...rest)
  }
  // Writes of the remembered workers fail while failWrites is set, as a full or forbidden storage would.
  const put = IDBObjectStore.prototype.put
  globalThis.failWrites = false
  IDBObjectStore.prototype.put = function (value, key) {
    if (globalThis.failWrites && key === 'workers') throw new DOMException('quota', 'QuotaExceededError')
    return put.call(this, value, key)
  }
}
const CHANGED = 'The remembered workers were changed in another tab: review again.'
const UNSAVED = 'This browser could not save the change to the remembered workers: they are listed as it holds them.'
const keys = (page) => page.$$eval('#workers code', (cs) => cs.map((c) => c.textContent))

test('renewal: a tab not yet told of another tab\'s change does not undo it, and signs nothing reviewed before it', { timeout: 180_000 }, async () => {
  const t = await open({ init: HOLD_STORAGE })
  try {
    await createIdentity(t.page)
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(1), scopes: 'post' })
    await authoriseAndSign(t.page, { agent: 'other', subject: workerPub(3), scopes: 'post' })
    const late = await t.tab(t.context)
    await late.waitForSelector('#renew:not([hidden])')
    assert.deepEqual(await keys(late), [workerPub(1), workerPub(3)])
    // The late tab hears nothing more. The first replaces forecaster's key; the late tab, still showing the old key,
    // forgets the other worker: the replaced key does not come back.
    await late.evaluate(() => { globalThis.holdStorage = true })
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    assert.deepEqual(await keys(late), [workerPub(1), workerPub(3)], 'the late tab has not been told')
    await forget(late, 1)
    assert.deepEqual((await kept(late)).map((w) => [w.agent, w.subject]), [['forecaster', workerPub(2)]])
    assert.deepEqual(await keys(late), [workerPub(2)], 'the late tab lists what storage holds')
    assert.equal(await late.textContent('#error'), '')
    await late.evaluate(() => { globalThis.holdStorage = false; for (const f of globalThis.heldStorage.splice(0)) f() })
    await t.page.waitForFunction(() => document.querySelectorAll('#workers li').length === 1)
    assert.deepEqual(await keys(t.page), [workerPub(2)])

    // Now the first tab is the late one. It reviews a renewal and a new worker; another tab then changes the workers.
    await authoriseAndSign(t.page, { agent: 'other', subject: workerPub(3), scopes: 'post' })
    await late.waitForFunction(() => document.querySelectorAll('#workers li').length === 2)
    await t.page.evaluate(() => { globalThis.holdStorage = true })
    const before = await signCount(t)
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await forget(late, 0)
    assert.equal((await kept(late)).length, 1)
    assert.equal(await t.page.isHidden('#renew-panel'), false, 'not told: the review is still shown')
    await t.page.click('#renew-sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), CHANGED)
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    assert.deepEqual(await keys(t.page), [workerPub(3)], 'brought up to date')
    assert.equal(await signCount(t), before, 'the passkey was not asked')
    // The same for one worker's review, and for either review started after the change.
    await authorise(t.page, { agent: 'w5', subject: workerPub(5), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await forget(late, 0)
    assert.equal((await kept(late)).length, 0)
    await t.page.click('#sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), CHANGED)
    assert.equal(await t.page.isHidden('#review-panel'), true)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.equal(await signCount(t), before)
    assert.deepEqual(await kept(t.page), [], 'nothing remembered of what was not signed')
    // Up to date again, the same review is signed.
    await authoriseAndSign(t.page, { agent: 'w5', subject: workerPub(5), scopes: 'post' })
    assert.equal(await signCount(t), before + 1)
    assert.equal(await t.page.textContent('#error'), '')
    // A change that arrives while the passkey is asked: the signature is not handed over, nor the worker remembered.
    await late.evaluate(() => { globalThis.holdStorage = true })
    const slowPasskey = () => t.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      navigator.credentials.get = async (o) => { globalThis.asking?.(); await new Promise((resolve) => { globalThis.answer = resolve }); return get(o) }
    })
    await slowPasskey()
    await authorise(t.page, { agent: 'w6', subject: workerPub(6), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.evaluate(() => { globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve }) })
    await t.page.click('#sign')
    await t.page.evaluate(() => globalThis.asked)
    await forget(late, 0)
    await t.page.evaluate(() => globalThis.answer())
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), CHANGED)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.equal(await t.page.isHidden('#review-panel'), true, 'the review is withdrawn (a surviving mutant)')
    assert.deepEqual(await kept(t.page), [])
    await seed(t.page, [stored(1), stored(2)])
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    await slowPasskey()
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await t.page.evaluate(() => { globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve }) })
    await t.page.click('#renew-sign')
    await t.page.evaluate(() => globalThis.asked)
    await seed(t.page, [stored(1)])
    await t.page.evaluate(() => globalThis.answer())
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), CHANGED)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    // A renewal withdrawn while the passkey was asked is dropped there: storage is not read for it, so nothing is
    // said of a change this tab has not been told of (a surviving mutant; the model's SignReply).
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await t.page.evaluate(() => { globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve }) })
    await t.page.click('#renew-sign')
    await t.page.evaluate(() => globalThis.asked)
    await t.page.locator('#workers input[type=checkbox]').first().click()
    await seed(t.page, [stored(1), stored(3)])
    await t.page.evaluate(() => globalThis.answer())
    await t.page.waitForTimeout(500)
    assert.equal(await t.page.textContent('#error'), '')
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

test('renewal: a change this browser cannot save is said, and the list stays as storage holds it', { timeout: 180_000 }, async () => {
  const t = await open({ init: HOLD_STORAGE })
  try {
    await createIdentity(t.page)
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(1), scopes: 'post' })
    assert.equal(await t.page.textContent('#error'), '')
    await t.page.evaluate(() => { globalThis.failWrites = true })
    // A new key signed while storage refuses: the old key is still the one remembered, so the new one is handed
    // nothing, and the page says why instead of promising the old key retired. The review stays, to be signed again.
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.click('#sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), UNSAVED)
    assert.equal(await t.page.isHidden('#handoff'), true, 'nothing handed over')
    assert.equal(await t.page.isHidden('#review-panel'), false)
    assert.deepEqual(await keys(t.page), [workerPub(1)])
    // A worker that cannot be forgotten stays listed, with the same notice. A Forget withdraws what is open when it
    // is pressed, saved or not (as the model of the page has it; a surviving mutant).
    await t.page.fill('#scopes', 'post read')
    assert.equal(await t.page.textContent('#error'), '')
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await forget(t.page, 0)
    assert.equal(await t.page.textContent('#error'), UNSAVED)
    assert.deepEqual(await keys(t.page), [workerPub(1)])
    assert.equal(await t.page.isHidden('#review-panel'), true)
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    assert.deepEqual(await keys(t.page), [workerPub(1)], 'as before the reload')
    // Saved again, nothing is said, and the worker has its hand-off.
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    assert.equal(JSON.parse(JSON.parse(await t.page.inputValue('#handoff')).payload).body.subject, workerPub(2))
    assert.equal(await t.page.textContent('#error'), '')
    assert.deepEqual(await keys(t.page), [workerPub(2)])
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Found by the generated histories of #72: what was reviewed can expire before it is signed, or while the passkey is
// asked. An expired delegation is not signed, nor handed over: the review is withdrawn, to be made again from now.
test('a review that has expired is not signed, and one that expires while the passkey is asked is not handed over', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    await authoriseAndSign(t.page, { agent: 'w1', subject: workerPub(1), scopes: 'post', days: '2' })
    const EXPIRED = 'What was reviewed has since expired: review again.'
    const slowPasskey = () => t.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve })
      navigator.credentials.get = async (o) => { globalThis.asking(); await new Promise((resolve) => { globalThis.answer = resolve }); navigator.credentials.get = get; return get(o) }
    })
    const before = await signCount(t)
    // One worker, a day's lifetime: a second short of a day later it is signed; at the day, it is not.
    await authorise(t.page, { agent: 'w2', subject: workerPub(2), scopes: 'post', days: '1' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    const exp = Date.parse(await t.page.textContent('#show-exp')) / 1000
    const at = (time) => t.page.evaluate((ms) => { Date.now = () => ms }, time * 1000)
    await at(exp)
    await t.page.click('#sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), EXPIRED)
    assert.equal(await t.page.isHidden('#review-panel'), true)
    assert.equal(await signCount(t), before, 'the passkey was not asked')
    // Expiring while the passkey is asked: signed, but not handed over or remembered.
    await at(exp - 86_400)
    await authorise(t.page, { agent: 'w2', subject: workerPub(2), scopes: 'post', days: '1' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await at(exp - 1)
    await slowPasskey()
    await t.page.click('#sign')
    await t.page.evaluate(() => globalThis.asked)
    await at(exp)
    await t.page.evaluate(() => globalThis.answer())
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), EXPIRED)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.equal((await kept(t.page)).length, 1)
    // A second before it expires, start to end, it is signed and handed over.
    await at(exp - 86_400)
    await authorise(t.page, { agent: 'w2', subject: workerPub(2), scopes: 'post', days: '1' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await at(exp - 1)
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    assert.equal((await kept(t.page)).length, 2)
    // A renewal: the same, at the expiry of the shortest-lived of those reviewed (w1 has two days, w2 one).
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    const exps = await t.page.$$eval('#renew-list > li', (lis) => lis.map((li) => Date.parse(li.querySelectorAll('dd')[3].textContent) / 1000))
    const signs = await signCount(t)
    await at(Math.min(...exps))
    await t.page.click('#renew-sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), EXPIRED)
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    assert.equal(await signCount(t), signs)
    await at(Math.min(...exps) - 86_400)
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await at(Math.min(...exps) - 1)
    await slowPasskey()
    await t.page.click('#renew-sign')
    await t.page.evaluate(() => globalThis.asked)
    await at(Math.min(...exps))
    await t.page.evaluate(() => globalThis.answer())
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), EXPIRED)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)

    // Expiry and withdrawal are looked at again after the passkey answers and the store has been asked, just before
    // anything is handed over. Another tab holds a transaction open on the store, so this tab's save (or its read
    // for a renewal) waits; what happens while it waits decides.
    const other = await t.tab(t.context)
    const holdStore = () => holdStoreIn(other)
    const freeStore = () => freeStoreIn(other)
    const base = Math.min(...exps)
    const signedWhileHeld = async (button) => {
      await slowPasskey()
      await t.page.click(button)
      await t.page.evaluate(() => globalThis.asked)
      await holdStore()
      await t.page.evaluate(() => globalThis.answer())
      await t.page.waitForTimeout(400) // the passkey has answered, and the page waits for the store
    }
    // A worker saved a moment before it expires, the answer coming after: remembered, since it was saved in time,
    // but not handed over.
    await at(base)
    await authorise(t.page, { agent: 'w7', subject: workerPub(7), scopes: 'post', days: '1' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await at(base + 86_400 - 1)
    await signedWhileHeld('#sign')
    await at(base + 86_400)
    await freeStore()
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), EXPIRED)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.deepEqual((await kept(t.page)).map((w) => w.agent), ['w1', 'w2', 'w7'])
    // Withdrawn by an edit while it is saved: remembered, not handed over, and nothing said.
    await at(base)
    await authorise(t.page, { agent: 'w8', subject: workerPub(8), scopes: 'post', days: '1' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await signedWhileHeld('#sign')
    await t.page.fill('#scopes', 'read')
    await freeStore()
    await t.page.waitForFunction(() => document.querySelectorAll('#workers li').length === 4)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.equal(await t.page.textContent('#error'), '')
    // A renewal whose read of the store returns after it has expired, or after it was withdrawn.
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    const least = Math.min(...await t.page.$$eval('#renew-list > li', (lis) => lis.map((li) => Date.parse(li.querySelectorAll('dd')[3].textContent) / 1000)))
    await at(least - 1)
    await signedWhileHeld('#renew-sign')
    await at(least)
    await freeStore()
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), EXPIRED)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    await at(base)
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await signedWhileHeld('#renew-sign')
    await t.page.locator('#workers input').nth(0).uncheck()
    await freeStore()
    await t.page.waitForTimeout(400)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    assert.equal(await t.page.textContent('#error'), '')
    // Unhurried, the same renewal is handed over.
    await t.page.locator('#workers input').nth(0).check()
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await signedWhileHeld('#renew-sign')
    await freeStore()
    await t.page.waitForSelector('#renew-handoffs:not([hidden])')
    assert.equal(await t.page.locator('#renew-handoffs textarea').count(), 4)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Found by the model (model/tla/IdPage.tla), in one tab: a review is made against the tab's copy of the workers, and
// the tab's own slow operations change that copy later. Whenever the copy changes, what is open is withdrawn, unless
// the change is the open review's own saving.
test('renewal: a review opened while this tab\'s own Forget or saving is still on its way is withdrawn when it lands', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(1), scopes: 'post' })
    await authoriseAndSign(t.page, { agent: 'other', subject: workerPub(3), scopes: 'post' })
    const other = await t.tab(t.context)
    await other.waitForSelector('#renew:not([hidden])')
    // Forget pressed on forecaster's row; before the store has answered, a new key for forecaster is reviewed, and
    // the review says it replaces the key just forgotten. When the Forget lands, that review is withdrawn.
    await holdStoreIn(other)
    await t.page.locator('#workers button').nth(0).click()
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.match(await t.page.textContent('#show-retires'), new RegExp(workerPub(1)))
    await freeStoreIn(other)
    await t.page.waitForSelector('#review-panel', { state: 'hidden' })
    assert.deepEqual(await keys(t.page), [workerPub(3)])
    // Reviewed again, it replaces nothing, and is signed.
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-retires'), '')
    // The passkey has answered and the saving waits for the store; meanwhile forecaster's first key is reviewed
    // again, against the list as it still is here (which says it replaces nothing). When the saving lands, the
    // list has forecaster under its second key, and that review is withdrawn; the saved worker is remembered.
    await t.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve })
      navigator.credentials.get = async (o) => { globalThis.asking(); await new Promise((resolve) => { globalThis.answer = resolve }); navigator.credentials.get = get; return get(o) }
    })
    await t.page.click('#sign')
    await t.page.evaluate(() => globalThis.asked)
    await holdStoreIn(other)
    await t.page.evaluate(() => globalThis.answer())
    await t.page.waitForTimeout(400) // the passkey has answered, and the page waits for the store
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(1), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-retires'), '')
    await freeStoreIn(other)
    await t.page.waitForSelector('#review-panel', { state: 'hidden' })
    assert.deepEqual(await keys(t.page), [workerPub(3), workerPub(2)])
    assert.equal(await t.page.isHidden('#handoff'), true, 'the saved worker\'s review was withdrawn: not handed over')
    assert.equal(await t.page.textContent('#error'), '')
    // An open review is left alone by an operation that changes nothing here: its own saving hands it over.
    await authoriseAndSign(t.page, { agent: 'w5', subject: workerPub(5), scopes: 'post' })
    assert.equal(await t.page.isHidden('#handoff'), false)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// A review is made against one state of the stored workers, counted: the same list reached again by later changes
// (a key replaced and put back) is not that state. And a Forget is of the row the tab shows, key and all: pressed in a
// tab not yet told that the row's key was replaced, it does not forget the new key's row.
test('renewal: a list put back as it was is a change all the same; a Forget does not reach a row it did not show', { timeout: 180_000 }, async () => {
  const t = await open({ init: HOLD_STORAGE })
  try {
    await createIdentity(t.page)
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(1), scopes: 'post' })
    await authoriseAndSign(t.page, { agent: 'other', subject: workerPub(3), scopes: 'post' })
    const late = await t.tab(t.context)
    await late.waitForSelector('#renew:not([hidden])')
    await late.evaluate(() => { globalThis.holdStorage = true })
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    // The late tab still shows forecaster under its first key, first in its list, and forgets that row.
    assert.deepEqual(await keys(late), [workerPub(1), workerPub(3)])
    await late.locator('#workers button').nth(0).click()
    await late.waitForFunction((k) => [...document.querySelectorAll('#workers code')].some((c) => c.textContent === k), workerPub(2))
    assert.deepEqual((await kept(late)).map((w) => [w.agent, w.subject]), [['other', workerPub(3)], ['forecaster', workerPub(2)]], 'the new key is still remembered')
    assert.deepEqual(await keys(late), [workerPub(3), workerPub(2)])
    await late.evaluate(() => { globalThis.holdStorage = false; for (const f of globalThis.heldStorage.splice(0)) f() })

    // A renewal reviewed; two changes later the stored list is the same again. It is not signed.
    const again = async () => { const now = await held(t.page, 'workers'); await hold(t.page, 'workers', { rev: now.rev + 2, workers: now.workers }) }
    const before = await signCount(t)
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    await again()
    await t.page.click('#renew-sign')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), CHANGED)
    assert.equal(await signCount(t), before)
    // The same while a worker's passkey is asked: the worker is neither remembered nor handed over.
    await authorise(t.page, { agent: 'w5', subject: workerPub(5), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      globalThis.asked = new Promise((resolve) => { globalThis.asking = resolve })
      navigator.credentials.get = async (o) => { globalThis.asking(); await new Promise((resolve) => { globalThis.answer = resolve }); navigator.credentials.get = get; return get(o) }
    })
    await t.page.click('#sign')
    await t.page.evaluate(() => globalThis.asked)
    await again()
    await t.page.evaluate(() => globalThis.answer())
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), CHANGED)
    assert.equal(await t.page.isHidden('#handoff'), true)
    assert.deepEqual((await kept(t.page)).map((w) => w.agent), ['other', 'forecaster'])
    // Each change the page commits counts one.
    const rev = (await held(t.page, 'workers')).rev
    await authoriseAndSign(t.page, { agent: 'w5', subject: workerPub(5), scopes: 'post' })
    await forget(t.page, 0)
    assert.equal((await held(t.page, 'workers')).rev, rev + 2)
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Found by the generated histories of #72: an added passkey's change, once signed, is submitted; a review begun
// while the witness is still answering withdraws it, and its hand-off is not shown when the answer comes.
test('an added passkey\'s hand-off is not shown if it was withdrawn while the change was submitted', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const a = await createIdentity(t.page)
    const d = await t.device()
    await d.page.click('#join-button')
    await d.page.waitForSelector('#joining:not([hidden])')
    const added = await d.page.inputValue('#join-root')
    let release = null
    let posted
    const seen = new Promise((resolve) => { posted = resolve })
    const held = new Promise((resolve) => { release = resolve })
    await t.page.route('**/v1/records', async (route) => { posted(); await held; await route.continue() })
    await t.page.fill('#new-root', added)
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    await t.page.click('#add-sign')
    await seen
    await t.page.fill('#agent', 'w1')
    assert.equal(await t.page.isHidden('#add-panel'), true)
    release()
    await idle(t.page)
    await t.page.waitForFunction(async () => true)
    for (let i = 0; i < 50 && (await t.witnessGet(`/v1/identities/${a.identity}/records`)).roots.length < 2; i++) await t.page.waitForTimeout(100)
    assert.equal((await t.witnessGet(`/v1/identities/${a.identity}/records`)).memberships.length, 1, 'signed, so submitted')
    await t.page.waitForTimeout(300)
    assert.equal(await t.page.isHidden('#add-handoff'), true)
    assert.equal(await t.page.textContent('#status'), 'Registered with the witness.')
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})

// Found by review of #71: the review of an added passkey waits for the witness too.
test('a new passkey\'s review edited while it waits for the witness is withdrawn, and its late error is not shown', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const a = await createIdentity(t.page)
    const roots = []
    for (let i = 0; i < 2; i++) {
      const d = await t.device()
      await d.page.click('#join-button')
      await d.page.waitForSelector('#joining:not([hidden])')
      roots.push(await d.page.inputValue('#join-root'))
    }
    let held = null
    let asked
    let release
    let down = false
    await t.page.route('**/v1/identities/*/records', async (route) => {
      if (held !== null) { asked(); await held }
      if (down) await route.fulfill({ status: 503, json: { ok: false, reason: 'unavailable' } })
      else await route.continue()
    })
    const unavailable = /^Failed to load resource: the server responded with a status of 503/
    const hold = () => { const seen = new Promise((resolve) => { asked = resolve }); held = new Promise((resolve) => { release = resolve }); return seen }
    const settled = async () => { release(); held = null; await idle(t.page); await t.page.waitForTimeout(300) }
    // Reviewed for one root, the field then names another while the witness is asked: nothing is shown or signable.
    let seen = hold()
    await t.page.fill('#new-root', roots[0])
    await t.page.click('#add-review')
    await seen
    await t.page.fill('#new-root', roots[1])
    await settled()
    assert.equal(await t.page.isHidden('#add-panel'), true)
    await t.page.evaluate(() => document.getElementById('add-sign').click())
    await t.page.waitForTimeout(500)
    assert.equal((await t.witnessGet(`/v1/identities/${a.identity}/records`)).memberships.length, 0)
    // A review that would be refused, edited while it waits: its refusal is of what is no longer there, and not shown.
    seen = hold()
    await t.page.fill('#new-root', 'not a root')
    await t.page.click('#add-review')
    await seen
    await t.page.fill('#new-root', roots[1])
    await settled()
    assert.equal(await t.page.textContent('#error'), '')
    // The same for a worker's review and a renewal's.
    seen = hold()
    await authorise(t.page, { agent: 'Not A Name', subject: workerPub(1), scopes: 'post' })
    await seen
    await t.page.fill('#agent', 'w1')
    await settled()
    assert.equal(await t.page.textContent('#error'), '')
    await seed(t.page, [stored(1, { scopes: ['attest'] })])
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    seen = hold()
    await t.page.click('#renew-review')
    await seen
    await t.page.locator('#workers input').nth(0).uncheck()
    await settled()
    assert.equal(await t.page.textContent('#error'), '')
    // The witness itself failing to answer a review since withdrawn: not shown, for each review; unwithdrawn, shown.
    down = true
    seen = hold()
    await t.page.fill('#new-root', roots[0])
    await t.page.click('#add-review')
    await seen
    await t.page.fill('#new-root', roots[1])
    await settled()
    assert.equal(await t.page.textContent('#error'), '', 'a new passkey')
    seen = hold()
    await authorise(t.page, { agent: 'w2', subject: workerPub(2), scopes: 'post' })
    await seen
    await t.page.fill('#agent', 'w3')
    await settled()
    assert.equal(await t.page.textContent('#error'), '', 'a worker')
    await t.page.locator('#workers input').nth(0).check()
    seen = hold()
    await t.page.click('#renew-review')
    await seen
    await t.page.locator('#workers input').nth(0).uncheck()
    await settled()
    assert.equal(await t.page.textContent('#error'), '', 'a renewal')
    await t.page.locator('#workers input').nth(0).check()
    seen = hold()
    await t.page.click('#renew-review')
    await seen
    await settled()
    assert.notEqual(await t.page.textContent('#error'), '', 'one not withdrawn says so')
    down = false
    // Unedited, the review is of the root in the field when Review was pressed.
    seen = hold()
    await t.page.fill('#new-root', roots[0])
    await t.page.click('#add-review')
    await seen
    await settled()
    assert.equal(await t.page.isHidden('#add-panel'), false)
    assert.deepEqual(t.problems.filter((p) => !unavailable.test(p)), [])
  } finally {
    await t.close()
  }
})

// Found by review: what storage holds is not trusted, and nothing of it is shown beside what the passkey signs unless
// it is a key: an entry whose key is not one is no worker.
test('renewal: a stored worker whose key is not a key is dropped; an unticked worker stays unticked until forgotten', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    await createIdentity(t.page)
    const prose = 'none. NOTE: the worker key shown above is abbreviated; it is the key you entered'
    await seed(t.page, [stored(1), stored(2, { agent: 'forecaster', subject: prose }), stored(3, { subject: 'AB'.repeat(32) }), stored(4, { subject: '00'.repeat(32).replace(/0$/, '2') })])
    await t.collect()
    await t.page.reload()
    await t.page.waitForSelector('#renew:not([hidden])')
    assert.deepEqual(await t.page.$$eval('#workers code', (cs) => cs.map((c) => c.textContent)), [workerPub(1)])
    await authorise(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await t.page.textContent('#show-retires'), '')
    // Unticked, a worker stays so when the list is drawn again (another is authorised, or forgotten), and is not renewed.
    await t.page.locator('#workers input').nth(0).uncheck()
    await authoriseAndSign(t.page, { agent: 'forecaster', subject: workerPub(2), scopes: 'post' })
    await authoriseAndSign(t.page, { agent: 'w5', subject: workerPub(5), scopes: 'post' })
    assert.deepEqual(await t.page.$$eval('#workers input', (bs) => bs.map((b) => b.checked)), [false, true, true])
    await forget(t.page, 2)
    assert.deepEqual(await t.page.$$eval('#workers input', (bs) => bs.map((b) => b.checked)), [false, true])
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    assert.deepEqual(await t.page.$$eval('#renew-list > li', (lis) => lis.map((li) => li.querySelector('dd').textContent)), ['forecaster'])
    // Forgotten and authorised again, it is a new entry: ticked.
    await forget(t.page, 0)
    await authoriseAndSign(t.page, { agent: 'w1', subject: workerPub(1), scopes: 'post' })
    assert.deepEqual(await t.page.$$eval('#workers input', (bs) => bs.map((b) => b.checked)), [true, true])
    assert.deepEqual(t.problems, [])
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
    await authoriseAndSign(t.page, { agent: 'w2', subject: workerPub(2) })
    await other.waitForFunction(() => document.querySelectorAll('#workers li').length === 2)
    // A review open in the first tab is withdrawn when the other tab forgets one of the two: the list is still shown,
    // the review is not, and its button signs nothing.
    await t.page.click('#renew-review')
    await t.page.waitForSelector('#renew-panel:not([hidden])')
    const before = await signCount(t)
    await forget(other, 0)
    await t.page.waitForFunction(() => document.querySelectorAll('#workers li').length === 1)
    assert.equal(await t.page.isHidden('#renew'), false)
    assert.equal(await t.page.isHidden('#renew-panel'), true)
    await t.page.evaluate(() => document.getElementById('renew-sign').click())
    await t.page.waitForTimeout(500)
    assert.equal(await t.page.isHidden('#renew-handoffs'), true)
    assert.equal(await signCount(t), before, 'nothing signed')
    await forget(other, 0)
    await t.page.waitForSelector('#renew', { state: 'hidden' })
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

// Histories (model/STATE.md §4): sequences of what a user does in two tabs of one browser, drawn at random, run
// against the page in Chrome, and judged after every step by what model/tla/IdPage.tla states of every reachable
// state. Storage is read directly after each step, so the judge knows each committed change and its order.
//   OneKeyPerAgent, NoLostUpdate, NoResurrection   storage after a step is exactly storage before it with that
//                                                  step's one change, or as it was;
//   ReviewedStateIsCurrent   a worker is saved, and a renewal handed over, only if nothing was committed since its
//                            review began;
//   ShownIsSaved             a saving retires exactly the keys its review said;
//   SavedBeforeHandover      a worker's hand-off is shown only with its row stored;
//   ViewHonest               a tab that hears lists what storage holds.
// And, so that a page that refuses everything does not pass: a review made by a tab that was up to date, with
// nothing committed and no notice reaching it since, is signed when asked.
// A tab made deaf hears no notices until it is let hear them (a late notice); a reload hears again.
const HISTORY_AGENTS = ['a', 'b']
const HISTORY_AUDS = ['https://x.example', 'https://y.example']
const rowOf = (w) => JSON.stringify([w.agent, w.aud, w.subject])
const commands = fc.array(fc.oneof(
  { weight: 6, arbitrary: fc.record({ do: fc.constant('review'), tab: fc.nat(1), agent: fc.nat(1), key: fc.integer({ min: 1, max: 2 }), aud: fc.nat(1) }) },
  { weight: 8, arbitrary: fc.record({ do: fc.constant('sign'), tab: fc.nat(1) }) },
  { weight: 2, arbitrary: fc.record({ do: fc.constant('forget'), tab: fc.nat(1), n: fc.nat(3) }) },
  { weight: 3, arbitrary: fc.record({ do: fc.constant('renew'), tab: fc.nat(1) }) },
  { weight: 4, arbitrary: fc.record({ do: fc.constant('renew-sign'), tab: fc.nat(1) }) },
  { weight: 1, arbitrary: fc.record({ do: fc.constant('untick'), tab: fc.nat(1), n: fc.nat(3) }) },
  { weight: 1, arbitrary: fc.record({ do: fc.constant('reload'), tab: fc.nat(1) }) },
  { weight: 3, arbitrary: fc.record({ do: fc.constant('deafen'), tab: fc.nat(1) }) },
  { weight: 2, arbitrary: fc.record({ do: fc.constant('hear'), tab: fc.nat(1) }) },
), { minLength: 8, maxLength: 16, size: 'max' })

// R11 at the page. The designation and the recovery are made here in Node with the page's own record builders: the
// identity's passkey signs by its private key, read from the virtual authenticator; the party and the root the
// recovery would install are keys held here.
test('a recovery under notice is shown on load with when it takes effect; one prompt cancels it; a witness that gives no answer is said; a change shows the designation it states', { timeout: 180_000 }, async () => {
  const t = await open()
  const unavailable = /^Failed to load resource: the server responded with a status of 503/
  try {
    const rpId = 'localhost'
    const MIN = membershipModule.MIN_RECOVERY_WINDOW
    const a = await createIdentity(t.page)
    const aId = rootModule.checkRoot(a.text, { rpId }).id
    assert.equal(await t.page.isHidden('#recovery-notice'), true)
    assert.equal(await t.page.isHidden('#notice-unchecked'), true, 'nothing was asked, and nothing is said of it')
    // With no notice shown, the cancel button (hidden) does nothing.
    await t.page.evaluate(() => document.getElementById('notice-cancel').click())
    await t.page.waitForTimeout(300)
    assert.equal(await t.page.textContent('#error'), '')
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    const aSecret = Buffer.from(createPrivateKey({ key: Buffer.from(credentials[0].privateKey, 'base64'), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' }).d, 'base64url')
    const secret = (name) => Uint8Array.from(createHash('sha256').update('P2 recovery ' + name).digest())
    const rootOf = (name) => envelope.wrap(envelope.seal('root', { pub: hex(p256.getPublicKey(secret(name), false)), rp_id: rpId }).payload)
    const by = (key, id) => makeAssertion({ covers: [id], ad: authData({ rpId }), cdj: clientData({ challenge: challengeFor([id]), origin: t.site.origin }), secret: key })
    const path = `/v1/identities/${a.identity}/records`
    const current = async () => pageRecords.currentMembership(await t.witnessGet(path), { identity: a.identity, rpId, origin: t.site.origin, witnessKeys: t.keys })
    const post = async (type, text, root) => {
      const r = await t.witnessPost('/v1/records', root === undefined ? { identity: a.identity, type, text } : { identity: a.identity, type, text, root })
      assert.equal(r.ok, true, `${type}: ${r.reason}`)
    }
    // The owner designates one party, a wait of three days and a second (not whole days, as another client may
    // state one: the page then gives it in seconds); it settles.
    const WAIT_S = MIN + 1
    const g = pageRecords.party(rootOf('g'), hex(secret('salt')), rpId)
    const d = pageRecords.designate({ identity: a.identity, state: await current(), parties: [g], threshold: 1, window: WAIT_S })
    await post('membership', pageRecords.rootSigned(d.payload, aId, by(aSecret, d.id)))
    t.advance(61)
    await t.svc.tick()
    assert.equal((await current()).recovery.threshold, 1)
    await t.page.reload()
    await t.page.waitForSelector('#identity:not([hidden])')
    await idle(t.page)
    assert.equal(await t.page.isHidden('#recovery-notice'), true, 'designated, and nothing under notice')
    assert.equal(await t.page.isHidden('#notice-unchecked'), true)
    // A change the page builds states the designation again, and shows it.
    await t.page.fill('#new-root', rootOf('b'))
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    assert.equal(await t.page.textContent('#add-recovery'), `1 of 1, after ${WAIT_S} seconds`)
    assert.equal(await t.page.textContent('#recovery-now'), `1 of 1, after ${WAIT_S} seconds`)
    await t.page.fill('#new-root', '')

    // The party asks for a recovery to a root of its choosing: the witness gives notice.
    const nId = rootModule.checkRoot(rootOf('n'), { rpId }).id
    const R = envelope.seal('membership', { identity: a.identity, prev: d.id, epoch: 3, roots: [nId] })
    await post('membership', pageRecords.partySigned(R.payload, g, by(secret('g'), R.id)), rootOf('g'))
    await post('root', rootOf('n'))
    await post('membership', pageRecords.rootSigned(R.payload, nId, by(secret('n'), R.id)))
    const noticed = await current()
    assert.equal(noticed.recovering.record, R.id)
    const iso = (s) => new Date(s * 1000).toISOString()

    // The witness gives no answer: the page says it could not ask, and shows no notice it does not have.
    t.outage('down')
    await t.page.reload()
    await t.page.waitForSelector('#notice-unchecked:not([hidden])')
    assert.equal(await t.page.isHidden('#recovery-notice'), true)
    t.outage()
    await t.page.click('#notice-retry')
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    assert.equal(await t.page.isHidden('#notice-unchecked'), true)
    // A syntactically broken 200 response is no answer too: silently treating it as no notice would hide the
    // recovery precisely when the page could not check the witness's state.
    await t.page.route('**/v1/identities/*/records', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{' }))
    await t.page.reload()
    await t.page.waitForSelector('#notice-unchecked:not([hidden])')
    assert.equal(await t.page.isHidden('#recovery-notice'), true)
    await t.page.unroute('**/v1/identities/*/records')
    await t.page.click('#notice-retry')
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    // So are records that are served and do not verify: only a 404 says the witness does not know the identity.
    await t.page.route('**/v1/identities/*/records', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
    await t.page.reload()
    await t.page.waitForSelector('#notice-unchecked:not([hidden])')
    assert.equal(await t.page.isHidden('#recovery-notice'), true)
    await t.page.unroute('**/v1/identities/*/records')
    await t.page.click('#notice-retry')
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    assert.equal(await t.page.textContent('#notice-record'), R.id)
    assert.equal(await t.page.textContent('#notice-at'), iso(noticed.recovering.at))
    assert.equal(await t.page.textContent('#notice-matures'), iso(noticed.recovering.at + WAIT_S))
    // On load, too; and in another tab of the browser.
    await t.page.reload()
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    const other = await t.tab(t.context)
    await other.waitForSelector('#recovery-notice:not([hidden])')

    // The notice is of the root it was asked for. Another root stored here (by another tab) is not shown it, even
    // before the witness has answered for that one; nor does the button, pressed then, sign anything.
    const mine = await held(t.page, 'root')
    const y = rootOf('y')
    const yId = rootModule.checkRoot(y, { rpId }).id
    const open1 = t.gate()
    await change(t.page, 'root', { credential: mine.credential, identity: rootModule.identityOf(yId), text: y, registered: true })
    await t.page.waitForFunction((id) => document.getElementById('identity-id').textContent === id, rootModule.identityOf(yId))
    await t.page.waitForSelector('#recovery-notice', { state: 'hidden' })
    assert.equal(await t.page.textContent('#recovery-now'), 'not known', 'nor the designation of the root held before')
    assert.equal(await t.page.textContent('#recheck-code'), '')
    await t.page.evaluate(() => document.getElementById('notice-cancel').click())
    await t.page.waitForTimeout(500)
    assert.equal(await t.page.textContent('#error'), '')
    open1()
    // The witness knows no such identity: that is an answer, and there is nothing to say.
    await idle(t.page)
    assert.equal(await t.page.isHidden('#notice-unchecked'), true)
    assert.equal(await t.page.isHidden('#recovery-notice'), true)
    assert.equal(await t.page.textContent('#error'), '', 'the button pressed for another root sent nothing')
    // A tab opened now has asked about that root only.
    const late = await t.tab(t.context)
    await late.waitForSelector('#identity:not([hidden])')
    await idle(late)
    assert.equal(await late.isHidden('#notice-unchecked'), true)
    // Asked for a change to it, the page says what the witness said.
    await late.click('#undesignate-review')
    await errorIs(late, 'the witness holds no record of this identity')
    // No root at all, with the old notice still in hand: the button does nothing.
    const open2 = t.gate()
    await change(t.page, 'root', mine)
    await change(t.page, 'root', null)
    await t.page.waitForSelector('#create:not([hidden])')
    await t.page.evaluate(() => document.getElementById('notice-cancel').click())
    open2()
    // The identity's own root stored again: the witness is asked again, and the notice is back.
    await change(t.page, 'root', mine)
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    await late.waitForSelector('#recovery-notice:not([hidden])')
    assert.equal((await t.witnessGet(path)).cancelled.length, 0, 'nothing was cancelled meanwhile')
    // No root at all, with that notice shown a moment ago: only creation is shown, nothing of the notice, and the
    // button does nothing and breaks nothing.
    const onlyCreation = async (why) => {
      await t.page.waitForSelector('#create:not([hidden])')
      for (const id of ['identity', 'joining', 'add-root', 'authorise', 'recovery', 'party', 'renew', 'recovery-notice', 'notice-unchecked']) assert.equal(await t.page.isHidden('#' + id), true, `${id}: ${why}`)
    }
    await change(t.page, 'root', null)
    await onlyCreation('no root, a notice in hand')
    await t.page.evaluate(() => document.getElementById('notice-cancel').click())
    await idle(t.page)
    assert.equal(await t.page.textContent('#error'), '')
    assert.deepEqual(t.problems.filter((p) => !unavailable.test(p) && !/status of (422|404)/.test(p)), [], 'no root is no error')
    // The witness gives no answer for the root stored again, and that is said; with no root, there is nothing to say.
    t.outage('down')
    await change(t.page, 'root', mine)
    await t.page.waitForSelector('#notice-unchecked:not([hidden])')
    await change(t.page, 'root', null)
    await onlyCreation('no root, an unanswered question in hand')
    t.outage()
    await change(t.page, 'root', mine)
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    await late.waitForSelector('#recovery-notice:not([hidden])')
    // An answer that comes late, for a root this tab no longer holds, says nothing of the root it holds now: the
    // witness is asked about another root, this identity's root is stored again and its notice shown, and only then
    // does the first question get its answer (that the witness could not be asked).
    let answerLate
    const asked = new Promise((resolve) => { answerLate = resolve })
    let waiting
    await t.page.route(`**/v1/identities/${rootModule.identityOf(yId)}/records`, (route) => { waiting = route; answerLate() })
    await change(t.page, 'root', { credential: mine.credential, identity: rootModule.identityOf(yId), text: y, registered: true })
    await asked
    await t.page.waitForSelector('#recovery-notice', { state: 'hidden' })
    await change(t.page, 'root', mine)
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    await waiting.fulfill({ status: 503, contentType: 'application/json', body: '{}' })
    await t.page.waitForTimeout(500)
    assert.equal(await t.page.isHidden('#recovery-notice'), false, 'the late answer does not take the notice down')
    assert.equal(await t.page.isHidden('#notice-unchecked'), true, 'nor is it said of this root that the witness could not be asked')
    await t.page.unroute(`**/v1/identities/${rootModule.identityOf(yId)}/records`)

    // A witness that refuses the cancel: said, and the notice stays.
    t.refusing(true)
    await t.page.click('#notice-cancel')
    await errorShown(t.page)
    assert.equal(await t.page.textContent('#error'), 'the witness refused the cancel: test')
    assert.equal(await t.page.isHidden('#recovery-notice'), false)
    t.refusing(false)
    // One prompt cancels it: the witness says so, the notice goes, and the identity is as it was.
    await t.page.click('#notice-cancel')
    await t.page.waitForSelector('#recovery-notice', { state: 'hidden' })
    assert.equal(await t.page.textContent('#status'), 'Cancel sent. The notice goes once the witness has said the recovery is cancelled.')
    assert.equal(await t.page.textContent('#error'), '')
    const kept = await t.witnessGet(path)
    assert.equal(kept.cancelled.length, 1)
    assert.equal(envelope.open(kept.cancelled[0], 'cancelled').body.record, R.id)
    const after = await current()
    assert.deepEqual([after.recovering, after.membership, after.authority], [null, d.id, [aId]])

    // A stored root that says it is joining is not asked about, whatever else is stored of it: a party asks again,
    // and a page loaded with such a root shows the joining passkey no notice.
    const mId = rootModule.checkRoot(rootOf('m'), { rpId }).id
    const R2 = envelope.seal('membership', { identity: a.identity, prev: d.id, epoch: 3, roots: [mId] })
    await post('membership', pageRecords.partySigned(R2.payload, g, by(secret('g'), R2.id)), rootOf('g'))
    await post('root', rootOf('m'))
    await post('membership', pageRecords.rootSigned(R2.payload, mId, by(secret('m'), R2.id)))
    assert.equal((await current()).recovering, null, 'after a cancel the witness gives no notice for three days')
    t.advance(3 * 86_400 + 1)
    await t.svc.tick()
    assert.equal((await current()).recovering.record, R2.id)
    await late.close()
    await other.close()
    await change(t.page, 'root', { ...mine, joining: true })
    await t.page.reload()
    await t.page.waitForSelector('#joining:not([hidden])')
    await idle(t.page)
    assert.deepEqual([await t.page.isHidden('#recovery-notice'), await t.page.isHidden('#notice-unchecked')], [true, true])
    await change(t.page, 'root', mine)
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    assert.equal(await t.page.textContent('#notice-record'), R2.id)

    // An identity that has ended (its owner cancelled this recovery, then contested a change of their own) has no
    // recovery to show: that is an answer, and nothing is said of the witness.
    await t.page.click('#notice-cancel')
    await t.page.waitForSelector('#recovery-notice', { state: 'hidden' })
    await t.svc.tick()
    const u = pageRecords.undesignate({ identity: a.identity, state: await current() })
    await post('membership', pageRecords.rootSigned(u.payload, aId, by(aSecret, u.id)))
    const contest = envelope.seal('contest', { identity: a.identity, record: u.id })
    await post('contest', pageRecords.rootSigned(contest.payload, aId, by(aSecret, contest.id)))
    t.advance(61)
    await t.svc.tick()
    t.advance(61)
    await t.svc.tick()
    await assert.rejects(current(), { message: 'this identity has ended' })
    await t.page.reload()
    await t.page.waitForSelector('#identity:not([hidden])')
    await idle(t.page)
    assert.deepEqual([await t.page.isHidden('#recovery-notice'), await t.page.isHidden('#notice-unchecked')], [true, true])
    assert.equal(await t.page.textContent('#recovery-now'), 'not known')
    await t.collect()
    assert.deepEqual(t.problems.filter((p) => !unavailable.test(p) && !/status of (422|404)/.test(p)), [], 'the browser reports only the answers the test arranged')
  } finally { await t.close() }
})

// R11 at the page, both sides: a passkey that is someone's recovery party, and the owner who designates it.
const statusIs = (page, text) => page.waitForFunction((text) => document.getElementById('status').textContent === text, text)
const errorIs = async (page, text) => { await errorShown(page); assert.equal(await page.textContent('#error'), text) }
// The page's passkey answers half a second late, until `prompt()` is called on the page again.
const slowPasskey = (page) => page.evaluate(() => {
  const get = navigator.credentials.get.bind(navigator.credentials)
  globalThis.prompt = () => { navigator.credentials.get = get }
  navigator.credentials.get = async (o) => { await new Promise((resolve) => setTimeout(resolve, 500)); return get(o) }
})
const promptPasskey = (page) => page.evaluate(() => globalThis.prompt())
// The page's next request matching `url` is held: `held()` resolves once it is made, with the function that lets it go.
async function holdNext (page, url) {
  let made
  const asked = new Promise((resolve) => { made = resolve })
  let first = true
  const handler = (route) => {
    if (!first) return route.fallback()
    first = false
    made(async (answer) => {
      if (answer === undefined) await route.continue(); else await route.fulfill(answer)
      await page.unroute(url, handler)
    })
  }
  await page.route(url, handler)
  return () => asked
}
const NO_ANSWER = { status: 503, contentType: 'application/json', body: '{}' }
async function proofOf (g, code) {
  await g.page.bringToFront()
  await g.page.fill('#proof-code', code)
  await g.page.click('#proof-review')
  await g.page.waitForSelector('#proof-panel:not([hidden])')
  assert.equal(await g.page.textContent('#proof-shown'), code)
  await g.page.click('#proof-sign')
  await g.page.waitForSelector('#proof:not([hidden])')
  return g.page.inputValue('#proof')
}
// A new card from the party's page. The card shown before is read before the button is pressed: read after, a page
// that had already made the new one would be waited on for another.
async function cardOf (g) {
  const was = await g.page.inputValue('#card')
  await g.page.click('#card-make')
  await g.page.waitForFunction((was) => { const c = document.getElementById('card'); return !c.hidden && c.value !== was }, was)
  return g.page.inputValue('#card')
}

test('recovery parties: a party gives a card and shows that its passkey is held; the owner designates it, checks it again, and ends the designation; the party the page made recovers', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const a = await createIdentity(t.page)
    const aId = rootModule.checkRoot(a.text, { rpId }).id
    const path = `/v1/identities/${a.identity}/records`
    const current = async () => pageRecords.currentMembership(await t.witnessGet(path), { identity: a.identity, rpId, origin: t.site.origin, witnessKeys: t.keys })
    const settle = async () => { t.advance(61); await t.svc.tick(); t.advance(61); await t.svc.tick() }
    await t.page.waitForFunction(() => document.getElementById('recovery-now').textContent === 'none')
    assert.equal(await t.page.textContent('#recheck-code'), a.identity)
    // The party: its own identity on its own device. Each card has a new salt, kept beside its root before it is shown.
    const g = await t.device()
    const gRoot = await createIdentity(g.page)
    const gId = rootModule.checkRoot(gRoot.text, { rpId }).id
    assert.equal(await g.page.isHidden('#card'), true)
    const card = await cardOf(g)
    const { root: cardRoot, salt } = JSON.parse(card)
    assert.equal(cardRoot, gRoot.text)
    assert.match(salt, /^[0-9a-f]{64}$/)
    assert.deepEqual((await held(g.page, 'root')).salts, [salt])
    const spare = await cardOf(g)
    assert.notEqual(JSON.parse(spare).salt, salt)
    assert.deepEqual((await held(g.page, 'root')).salts, [salt, JSON.parse(spare).salt])
    // A passkey that has given out as many cards as it keeps gives no more, and says so.
    const kept32 = await held(g.page, 'root')
    await change(g.page, 'root', { ...kept32, salts: [...kept32.salts, ...Array.from({ length: 30 }, (_, i) => hex(createHash('sha256').update('salt ' + i).digest()))] })
    await g.page.waitForTimeout(300)
    await g.page.click('#card-make')
    await errorIs(g.page, 'this passkey has given out 32 recovery cards, the most it keeps')
    assert.equal((await held(g.page, 'root')).salts.length, 32)
    assert.equal(await g.page.inputValue('#card'), spare, 'no card is shown for a salt that was not kept')

    // The owner: no card, a card that is none, the owner's own passkey as its party.
    await t.page.bringToFront()
    // Nothing reviewed: the signing button (hidden) does nothing.
    await t.page.evaluate(() => document.getElementById('designate-sign').click())
    await idle(t.page)
    assert.equal(await t.page.textContent('#error'), '')
    // A review of a designation withdraws whatever else was under review, even one that is refused.
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.click('#designate-review')
    await errorIs(t.page, 'name 1 to 3 recovery parties')
    assert.equal(await t.page.isHidden('#review-panel'), true)
    await t.page.fill('#party-cards', 'x')
    await t.page.click('#designate-review')
    await errorIs(t.page, 'that is not a recovery card')
    await t.page.fill('#party-cards', JSON.stringify({ root: a.text, salt }))
    await t.page.click('#designate-review')
    await errorIs(t.page, "a recovery party must not be one of this identity's own passkeys")
    await t.page.fill('#party-cards', card)
    await t.page.fill('#recovery-days', '2')
    await t.page.click('#designate-review')
    await errorIs(t.page, 'the waiting period must be 3 to 90 days')
    // The card, with blank lines about it, and three and a half days: what will be signed is shown.
    await t.page.fill('#party-cards', `\n  ${card}  \n \n`)
    await t.page.fill('#recovery-days', '3.5')
    await t.page.click('#designate-review')
    await t.page.waitForSelector('#designate-panel:not([hidden])')
    assert.equal(await t.page.textContent('#error'), '')
    assert.equal(await t.page.textContent('#designate-recovery'), '1 of 1, after 302400 seconds')
    assert.equal(await t.page.textContent('#designate-roots'), aId)
    assert.equal(await t.page.textContent('#designate-epoch'), '2')
    assert.equal(await t.page.isHidden('#designate-proofs-part'), false)
    // Any edit withdraws it.
    for (const [field, value] of [['#party-cards', card + ' '], ['#recovery-days', '14']]) {
      await t.page.fill(field, value)
      assert.equal(await t.page.isHidden('#designate-panel'), true, field)
      await t.page.click('#designate-review')
      await t.page.waitForSelector('#designate-panel:not([hidden])')
    }
    assert.equal(await t.page.textContent('#designate-recovery'), '1 of 1, after 14 days')
    const code = await t.page.textContent('#designate-code')
    const expected = pageRecords.designate({ identity: a.identity, state: await current(), parties: [pageRecords.fromCard(card, rpId)], threshold: 1, window: 14 * 86_400 })
    assert.equal(code, expected.id)
    // Unsigned until the party has shown that it holds its passkey: nothing asks the owner's passkey before.
    const signs = await signCount(t)
    await t.page.click('#designate-sign')
    await errorIs(t.page, '1 of the parties have not shown that they hold their passkey')
    // The party's side: a code that is none; then what it signs is the code's possession value, not the code.
    await g.page.bringToFront()
    await g.page.evaluate(() => document.getElementById('proof-sign').click())
    await g.page.fill('#proof-code', 'x')
    await g.page.click('#proof-review')
    await errorIs(g.page, 'a record id is 64 lowercase hex digits')
    assert.equal(await g.page.isHidden('#proof-panel'), true)
    await idle(g.page)
    assert.equal(await g.page.textContent('#error'), 'a record id is 64 lowercase hex digits', 'the button (hidden) did nothing, and cleared nothing')
    const gSigns = await signCount(g)
    // A review of the code withdraws whatever else was under review; spaces about the code are not part of it.
    await g.page.fill('#proof-code', ` ${code} `)
    await authorise(g.page)
    await g.page.waitForSelector('#review-panel:not([hidden])')
    await g.page.click('#proof-review')
    await g.page.waitForSelector('#proof-panel:not([hidden])')
    assert.equal(await g.page.isHidden('#review-panel'), true)
    assert.equal(await g.page.textContent('#proof-shown'), code)
    // An edit while the passkey is signing: what it signed is not shown.
    await slowPasskey(g.page)
    await g.page.click('#proof-sign')
    await g.page.fill('#proof-code', code)
    await g.page.waitForTimeout(1500)
    assert.equal(await signCount(g), gSigns + 1, 'the passkey did sign')
    assert.equal(await g.page.isHidden('#proof'), true)
    await promptPasskey(g.page)
    // A passkey that fails is said; signing again clears what was said, whatever it was.
    await g.page.click('#proof-review')
    await g.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      navigator.credentials.get = async () => { navigator.credentials.get = get; throw new Error('the passkey failed') }
    })
    await g.page.click('#proof-sign')
    await errorIs(g.page, 'the passkey failed')
    assert.equal(await g.page.isHidden('#proof'), true)
    const proof = await proofOf(g, code)
    assert.equal(await signCount(g), gSigns + 2, 'nothing was signed before the review')
    await g.page.click('#card-make')
    await errorIs(g.page, 'this passkey has given out 32 recovery cards, the most it keeps')
    await g.page.click('#proof-sign')
    await g.page.waitForFunction(() => document.getElementById('error').textContent === '')
    assert.deepEqual(JSON.parse(proof).covers, [pageRecords.possessionId(code)])
    await g.page.fill('#proof-code', code + ' ')
    assert.equal(await g.page.isHidden('#proof-panel'), true, 'an edit withdraws it')
    assert.equal(await g.page.isHidden('#proof'), true)
    const other = await proofOf(g, a.identity)
    // The owner: an answer for another code shows nothing; the right one, among other lines, does.
    await t.page.bringToFront()
    await t.page.fill('#designate-proofs', other)
    await t.page.click('#designate-sign')
    await errorIs(t.page, '1 of the parties have not shown that they hold their passkey')
    assert.equal(await signCount(t), signs)
    assert.equal(await t.page.isHidden('#designate-panel'), false, 'what they gave back is no edit of the change')
    await t.page.fill('#designate-proofs', `${other}\n ${proof} \n`)
    // An edit while the passkey is signing withdraws the change: the late signature is sent nowhere.
    await slowPasskey(t.page)
    await t.page.click('#designate-sign')
    await t.page.fill('#recovery-days', '15')
    await t.page.waitForTimeout(1500)
    await idle(t.page)
    assert.equal(await signCount(t), signs + 1, 'the passkey did sign')
    assert.equal((await t.witnessGet(path)).memberships.length, 0, 'and what it signed was not sent')
    assert.equal(await t.page.textContent('#status'), '')
    await promptPasskey(t.page)
    await t.page.fill('#recovery-days', '14')
    await t.page.click('#designate-review')
    await t.page.waitForSelector('#designate-panel:not([hidden])')
    assert.equal(await t.page.textContent('#designate-code'), code)
    // A review withdrawn while the witness is asked is not shown its late refusal.
    for (const answer of [NO_ANSWER, undefined]) {
      const asked = await holdNext(t.page, `**${path}`)
      await t.page.click('#designate-review')
      const go = await asked()
      await t.page.fill('#recovery-days', '15')
      await go(answer)
      await idle(t.page)
      assert.equal(await t.page.textContent('#error'), '')
      assert.equal(await t.page.isHidden('#designate-panel'), true, 'nor its late answer')
    }
    await t.page.fill('#recovery-days', '14')
    await t.page.click('#designate-review')
    await t.page.waitForSelector('#designate-panel:not([hidden])')
    await t.page.click('#designate-sign')
    await statusIs(t.page, 'Signed. The change settles once its contest window has passed.')
    assert.equal(await t.page.textContent('#error'), '')
    assert.equal(await t.page.isHidden('#designate-handoff'), true, 'one passkey: nobody is left to co-sign')
    assert.equal(await signCount(t), signs + 2)
    await settle()
    assert.deepEqual((await current()).recovery, expected.body.recovery)
    assert.equal((await current()).membership, code)

    // Loaded again, the page says what is designated; the same check is made over the current membership.
    await t.page.reload()
    await t.page.waitForFunction(() => document.getElementById('recovery-now').textContent === '1 of 1, after 14 days')
    assert.equal(await t.page.textContent('#recheck-code'), code)
    await t.page.click('#recheck')
    await errorIs(t.page, 'paste the recovery cards of the parties to check')
    await t.page.fill('#party-cards', card)
    // The check withdraws whatever was under review.
    await authorise(t.page)
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.click('#recheck')
    await statusIs(t.page, '0 of 1 of these parties showed that they hold their passkey.')
    assert.equal(await t.page.isHidden('#review-panel'), true)
    // Withdrawn while the witness is asked, it says nothing of the late answer, a refusal or not.
    for (const answer of [NO_ANSWER, undefined]) {
      const asked = await holdNext(t.page, `**${path}`)
      await t.page.click('#recheck')
      const go = await asked()
      await t.page.fill('#party-cards', card + ' ')
      await go(answer)
      await idle(t.page)
      assert.deepEqual([await t.page.textContent('#status'), await t.page.textContent('#error')], ['', ''])
      await t.page.fill('#party-cards', card)
    }
    await t.page.click('#recheck')
    await statusIs(t.page, '0 of 1 of these parties showed that they hold their passkey.')
    const again = await proofOf(g, code)
    await t.page.bringToFront()
    await t.page.fill('#recheck-proofs', `${other}\n${again}`)
    await t.page.click('#recheck')
    await statusIs(t.page, '1 of 1 of these parties showed that they hold their passkey.')
    assert.equal(await t.page.textContent('#error'), '')
    await t.page.fill('#party-cards', `${card}\n${spare}`)
    await t.page.click('#recheck')
    await errorIs(t.page, "a card here is not one of this identity's recovery parties")
    assert.equal(await t.page.textContent('#status'), '', 'the last check is not left standing')

    // The party the page made recovers: its key and the card's salt open the commitment, and notice is given.
    const { credentials } = await g.cdp.send('WebAuthn.getCredentials', { authenticatorId: g.authenticatorId })
    const gSecret = Buffer.from(createPrivateKey({ key: Buffer.from(credentials[0].privateKey, 'base64'), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' }).d, 'base64url')
    const nSecret = Uint8Array.from(createHash('sha256').update('P2 designate n').digest())
    const nRoot = envelope.wrap(envelope.seal('root', { pub: hex(p256.getPublicKey(nSecret, false)), rp_id: rpId }).payload)
    const by = (key, id) => makeAssertion({ covers: [id], ad: authData({ rpId }), cdj: clientData({ challenge: challengeFor([id]), origin: t.site.origin }), secret: key })
    const R = envelope.seal('membership', { identity: a.identity, prev: code, epoch: 3, roots: [rootModule.checkRoot(nRoot, { rpId }).id] })
    const post = async (body) => { const r = await t.witnessPost('/v1/records', { identity: a.identity, ...body }); assert.equal(r.ok, true, r.reason) }
    await post({ type: 'membership', text: pageRecords.partySigned(R.payload, pageRecords.fromCard(card, rpId), by(gSecret, R.id)), root: gRoot.text })
    await post({ type: 'root', text: nRoot })
    await post({ type: 'membership', text: pageRecords.rootSigned(R.payload, rootModule.checkRoot(nRoot, { rpId }).id, by(nSecret, R.id)) })
    await t.svc.tick()
    assert.equal((await current()).recovering.record, R.id)
    assert.equal(gId, pageRecords.fromCard(card, rpId).root)
    await t.page.reload()
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    await t.page.click('#notice-cancel')
    await statusIs(t.page, 'Cancel sent. The notice goes once the witness has said the recovery is cancelled.')
    await t.svc.tick()

    // Ending the designation: the same change without one, and no party is asked anything.
    await t.page.click('#undesignate-review')
    await t.page.waitForSelector('#designate-panel:not([hidden])')
    assert.equal(await t.page.textContent('#designate-recovery'), 'none')
    assert.equal(await t.page.textContent('#designate-epoch'), '3')
    assert.equal(await t.page.isHidden('#designate-proofs-part'), true)
    t.refusing(true)
    await t.page.click('#designate-sign')
    await errorIs(t.page, 'the witness refused the membership: test')
    assert.equal(await t.page.textContent('#status'), '', 'nothing said of an earlier signing is left standing')
    t.refusing(false)
    await t.page.click('#designate-sign')
    await statusIs(t.page, 'Signed. The change settles once its contest window has passed.')
    await settle()
    assert.equal((await current()).recovery, null)
    await t.page.click('#undesignate-review')
    await errorIs(t.page, 'no recovery parties are designated')
    assert.deepEqual(t.problems.filter((p) => !/status of (422 \(Unprocessable Entity\)|503 \(Service Unavailable\))$/.test(p)), [])
  } finally { await t.close() }
})

test('recovery parties, two passkeys: one designates and hands the change over; the other co-signs only a change that sets the parties and nothing else', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const a = await createIdentity(t.page)
    const aId = rootModule.checkRoot(a.text, { rpId }).id
    const path = `/v1/identities/${a.identity}/records`
    const current = async () => pageRecords.currentMembership(await t.witnessGet(path), { identity: a.identity, rpId, origin: t.site.origin, witnessKeys: t.keys })
    // A second passkey joins, and the change settles.
    const b = await t.device()
    await b.page.click('#join-button')
    await b.page.waitForSelector('#joining:not([hidden])')
    assert.deepEqual([await b.page.isHidden('#recovery'), await b.page.isHidden('#party')], [true, true], 'a joining passkey designates nothing and is nobody\'s party')
    const bId = rootModule.checkRoot(await b.page.inputValue('#join-root'), { rpId }).id
    await t.page.bringToFront()
    await t.page.fill('#new-root', await b.page.inputValue('#join-root'))
    await t.page.click('#add-review')
    await t.page.waitForSelector('#add-panel:not([hidden])')
    await t.page.click('#add-sign')
    await t.page.waitForSelector('#add-handoff:not([hidden])')
    await b.page.bringToFront()
    await b.page.fill('#cosign-payload', await t.page.inputValue('#add-handoff'))
    await b.page.click('#cosign-review')
    await b.page.waitForSelector('#cosign-panel:not([hidden])')
    await b.page.click('#cosign-sign')
    await b.page.waitForSelector('#identity:not([hidden])')
    assert.deepEqual([await b.page.isHidden('#recovery'), await b.page.isHidden('#party')], [false, false])
    t.advance(61)
    await t.svc.tick()
    const two = await current()
    assert.deepEqual(two.authority, [aId, bId].sort())

    // A party; the first passkey designates it, and is told to co-sign with the other.
    const g = await t.device()
    await createIdentity(g.page)
    const card = await cardOf(g)
    await t.page.bringToFront()
    await t.page.fill('#party-cards', card)
    await t.page.click('#designate-review')
    await t.page.waitForSelector('#designate-panel:not([hidden])')
    assert.equal(await t.page.textContent('#designate-roots'), [aId, bId].sort().join(' '))
    const code = await t.page.textContent('#designate-code')
    const proof = await proofOf(g, code)
    await t.page.bringToFront()
    await t.page.fill('#designate-proofs', proof)
    // An edit while the witness is given the signed change: it has it, and no hand-off of what was withdrawn is shown.
    const given = await holdNext(t.page, '**/v1/records')
    await t.page.click('#designate-sign')
    const take = await given()
    await t.page.fill('#recovery-days', '15')
    await take()
    await idle(t.page)
    assert.deepEqual([await t.page.textContent('#status'), await t.page.isHidden('#designate-handoff'), await t.page.textContent('#error')], ['', true, ''])
    await t.page.fill('#recovery-days', '14')
    await t.page.click('#designate-review')
    await t.page.waitForSelector('#designate-panel:not([hidden])')
    assert.equal(await t.page.textContent('#designate-code'), code)
    await t.page.click('#designate-sign')
    await statusIs(t.page, 'Signed. Co-sign this change with your other passkeys.')
    assert.equal(await t.page.isHidden('#designate-handoff'), false)
    const payload = await t.page.inputValue('#designate-handoff')
    const d = pageRecords.changeToSign(payload)
    assert.equal(d.id, code)
    assert.equal((await current()).membership, two.membership, 'one of two has changed nothing')
    // An edit after signing withdraws the hand-off.
    await t.page.fill('#recovery-days', '15')
    assert.equal(await t.page.isHidden('#designate-handoff'), true)

    // The other passkey: nothing is signed before a review; a change of the roots is no change of the parties.
    await b.page.bringToFront()
    await b.page.evaluate(() => document.getElementById('recovery-cosign-sign').click())
    await idle(b.page)
    assert.equal(await b.page.textContent('#error'), '')
    await b.page.fill('#recovery-cosign-payload', 'x')
    await b.page.click('#recovery-cosign-review')
    await errorIs(b.page, 'that is not a membership change')
    for (const over of [{ roots: [bId] }, { epoch: d.body.epoch + 1 }, { prev: a.identity }]) {
      await b.page.fill('#recovery-cosign-payload', envelope.seal('membership', { ...d.body, ...over }).payload)
      await b.page.click('#recovery-cosign-review')
      await errorIs(b.page, "that change does more than set this identity's recovery parties")
      assert.equal(await b.page.isHidden('#recovery-cosign-panel'), true)
    }
    const signs = await signCount(b)
    await b.page.fill('#recovery-cosign-payload', ` ${payload} `)
    await authorise(b.page)
    await b.page.waitForSelector('#review-panel:not([hidden])')
    await b.page.click('#recovery-cosign-review')
    await b.page.waitForSelector('#recovery-cosign-panel:not([hidden])')
    assert.equal(await b.page.isHidden('#review-panel'), true, 'the review withdraws whatever else was under review')
    assert.equal(await b.page.textContent('#error'), '')
    assert.equal(await b.page.textContent('#recovery-cosign-recovery'), '1 of 1, after 14 days')
    assert.equal(await b.page.textContent('#recovery-cosign-roots'), [aId, bId].sort().join(' '))
    assert.equal(await b.page.textContent('#recovery-cosign-epoch'), '3')
    await b.page.fill('#recovery-cosign-payload', payload)
    assert.equal(await b.page.isHidden('#recovery-cosign-panel'), true, 'an edit withdraws it')
    await b.page.click('#recovery-cosign-review')
    await b.page.waitForSelector('#recovery-cosign-panel:not([hidden])')
    assert.equal(await signCount(b), signs)
    // A review withdrawn while the witness is asked is not shown its late refusal.
    for (const answer of [NO_ANSWER, undefined]) {
      const asked = await holdNext(b.page, `**${path}`)
      await b.page.click('#recovery-cosign-review')
      const go = await asked()
      await b.page.fill('#recovery-cosign-payload', payload + ' ')
      await go(answer)
      await idle(b.page)
      assert.deepEqual([await b.page.textContent('#error'), await b.page.isHidden('#recovery-cosign-panel')], ['', true], 'nor its late answer')
    }
    await b.page.click('#recovery-cosign-review')
    await b.page.waitForSelector('#recovery-cosign-panel:not([hidden])')
    // An edit while the passkey is signing withdraws it: the late signature is sent nowhere.
    const sent = (await t.witnessGet(path)).memberships.length
    await slowPasskey(b.page)
    await b.page.click('#recovery-cosign-sign')
    await b.page.fill('#recovery-cosign-payload', payload)
    await b.page.waitForTimeout(1500)
    await idle(b.page)
    assert.equal(await signCount(b), signs + 1, 'the passkey did sign')
    assert.deepEqual([(await t.witnessGet(path)).memberships.length, await b.page.textContent('#status')], [sent, ''])
    await promptPasskey(b.page)
    await b.page.click('#recovery-cosign-review')
    await b.page.waitForSelector('#recovery-cosign-panel:not([hidden])')
    // A witness that refuses is shown, and nothing said of an earlier signing is left standing.
    t.refusing(true)
    await b.page.click('#recovery-cosign-sign')
    await errorIs(b.page, 'the witness refused the membership: test')
    assert.equal(await b.page.textContent('#status'), '')
    t.refusing(false)
    await b.page.click('#recovery-cosign-sign')
    await statusIs(b.page, 'Co-signed. The change settles once its contest window has passed.')
    assert.equal(await b.page.textContent('#error'), '')
    assert.equal(await signCount(b), signs + 3)
    t.advance(61)
    await t.svc.tick()
    t.advance(61)
    await t.svc.tick()
    const after = await current()
    assert.deepEqual([after.membership, after.recovery], [code, d.body.recovery])
    assert.deepEqual(t.problems.filter((p) => !/status of (422 \(Unprocessable Entity\)|503 \(Service Unavailable\))$/.test(p)), [])
  } finally { await t.close() }
})

test('recovery at the page: a new passkey asks, the party signs what it is shown, the new passkey signs after it; the owner sees the notice; uncancelled, the identity is the new passkey\'s', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const MIN = membershipModule.MIN_RECOVERY_WINDOW
    const a = await createIdentity(t.page)
    const aId = rootModule.checkRoot(a.text, { rpId }).id
    const path = `/v1/identities/${a.identity}/records`
    const current = async () => pageRecords.currentMembership(await t.witnessGet(path), { identity: a.identity, rpId, origin: t.site.origin, witnessKeys: t.keys })
    // The party, with a card its page made; the owner designates it (here in Node, with the owner's passkey).
    const g = await t.device()
    const gRoot = await createIdentity(g.page)
    const card = await cardOf(g)
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    const aSecret = Buffer.from(createPrivateKey({ key: Buffer.from(credentials[0].privateKey, 'base64'), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' }).d, 'base64url')
    const by = (key, id) => makeAssertion({ covers: [id], ad: authData({ rpId }), cdj: clientData({ challenge: challengeFor([id]), origin: t.site.origin }), secret: key })
    const d = pageRecords.designate({ identity: a.identity, state: await current(), parties: [pageRecords.fromCard(card, rpId)], threshold: 1, window: MIN })
    assert.equal((await t.witnessPost('/v1/records', { identity: a.identity, type: 'membership', text: pageRecords.rootSigned(d.payload, aId, by(aSecret, d.id)) })).ok, true)
    t.advance(61)
    await t.svc.tick()
    assert.equal((await current()).membership, d.id)

    // Every passkey lost: a new one, on a new device, asks for the identity.
    const n = await t.device()
    await n.page.click('#join-button')
    await n.page.waitForSelector('#joining:not([hidden])')
    const nRoot = await n.page.inputValue('#join-root')
    const nId = rootModule.checkRoot(nRoot, { rpId }).id
    const print = await n.page.textContent('#join-fingerprint')
    await n.page.evaluate(() => document.getElementById('recover-sign').click())
    await n.page.fill('#recover-identity', 'x')
    await n.page.click('#recover-review')
    await errorIs(n.page, 'an identity is 64 lowercase hex digits')
    await n.page.fill('#recover-identity', gRoot.identity)
    await n.page.click('#recover-review')
    await errorIs(n.page, 'that identity has designated no recovery parties')
    await n.page.fill('#recover-identity', ` ${a.identity} `)
    await n.page.click('#recover-review')
    await n.page.waitForSelector('#recover-panel:not([hidden])')
    assert.equal(await n.page.textContent('#error'), '')
    assert.equal(await n.page.textContent('#recover-shown'), a.identity)
    assert.equal(await n.page.textContent('#recover-roots'), nId)
    assert.equal(await n.page.textContent('#recover-recovery'), '1 of 1, after 3 days')
    assert.equal(await n.page.textContent('#recover-wait'), '3 days after enough parties and this passkey have signed, unless a passkey the identity has now cancels it')
    const request = await n.page.inputValue('#recover-request')
    const R = pageRecords.changeToSign(request)
    assert.deepEqual(R.body, { identity: a.identity, prev: d.id, epoch: 3, roots: [nId], recovery: d.body.recovery })
    await n.page.fill('#recover-identity', a.identity)
    assert.equal(await n.page.isHidden('#recover-panel'), true, 'an edit withdraws it')
    await n.page.click('#recover-review')
    await n.page.waitForSelector('#recover-panel:not([hidden])')
    assert.equal(await n.page.inputValue('#recover-request'), request)
    // A review that fails withdraws the one shown; an identity is the whole of what is typed.
    t.outage('down')
    await n.page.click('#recover-review')
    await errorIs(n.page, 'the witness did not answer')
    assert.equal(await n.page.isHidden('#recover-panel'), true)
    t.outage()
    for (const typed of ['0' + a.identity, a.identity + '0']) {
      await n.page.fill('#recover-identity', typed)
      await n.page.click('#recover-review')
      await errorIs(n.page, 'an identity is 64 lowercase hex digits')
    }
    // Withdrawn while the witness is asked, it shows nothing of the late answer, a refusal or not.
    await n.page.fill('#recover-identity', a.identity)
    for (const answer of [NO_ANSWER, undefined]) {
      const asked = await holdNext(n.page, `**${path}`)
      await n.page.click('#recover-review')
      const go = await asked()
      await n.page.fill('#recover-identity', a.identity + ' ')
      await go(answer)
      await idle(n.page)
      assert.deepEqual([await n.page.textContent('#error'), await n.page.isHidden('#recover-panel')], ['', true])
    }
    const review = async () => { await n.page.click('#recover-review'); await n.page.waitForSelector('#recover-panel:not([hidden])') }
    await review()
    // A passkey that fails is said, and nothing is kept; nor is what it signs after an edit.
    const before = await signCount(n)
    await n.page.evaluate(() => {
      const get = navigator.credentials.get.bind(navigator.credentials)
      navigator.credentials.get = async () => { navigator.credentials.get = get; throw new Error('the passkey failed') }
    })
    await n.page.click('#recover-sign')
    await errorIs(n.page, 'the passkey failed')
    await slowPasskey(n.page)
    await n.page.click('#recover-sign')
    await n.page.fill('#recover-identity', a.identity)
    await n.page.waitForTimeout(1500)
    await idle(n.page)
    assert.equal(await signCount(n), before + 1, 'the passkey did sign')
    assert.deepEqual([await n.page.isHidden('#cosign-pending'), (await held(n.page, 'root')).cosigned], [true, undefined])
    await promptPasskey(n.page)
    await review()
    // Signed before any party has: kept, refused by the witness, and waiting to be sent again.
    const nSigns = await signCount(n)
    await n.page.click('#recover-sign')
    await errorIs(n.page, 'the witness refused the membership: signer')
    await n.page.waitForSelector('#cosign-pending:not([hidden])')
    assert.equal(await signCount(n), nSigns + 1)
    assert.equal((await current()).recovering, null)

    // The party: what is no request; a card that is not its own; a browser that lost the salt, and the card given back.
    await g.page.bringToFront()
    await g.page.evaluate(() => document.getElementById('rescue-sign').click())
    await g.page.fill('#rescue-request', 'x')
    await g.page.click('#rescue-review')
    await errorIs(g.page, 'that is not a membership change')
    const kept = await held(g.page, 'root')
    const { salts, ...bare } = kept
    await change(g.page, 'root', bare)
    await g.page.waitForTimeout(300)
    await g.page.fill('#rescue-request', request)
    await g.page.click('#rescue-review')
    await errorIs(g.page, "this passkey is not one of that identity's recovery parties")
    await g.page.fill('#rescue-card', JSON.stringify({ root: a.text, salt: salts[0] }))
    await g.page.click('#rescue-review')
    await errorIs(g.page, "that recovery card is not this passkey's")
    await g.page.fill('#rescue-card', card)
    await g.page.click('#rescue-review')
    await g.page.waitForSelector('#rescue-panel:not([hidden])')
    await g.page.fill('#rescue-card', '')
    assert.equal(await g.page.isHidden('#rescue-panel'), true, 'an edit withdraws it')
    // With the salt it kept: what will be signed is shown, with the fingerprint the new device shows.
    await change(g.page, 'root', kept)
    await g.page.waitForTimeout(300)
    await g.page.fill('#rescue-request', ` ${request} `)
    await g.page.fill('#rescue-card', ' ')
    // A review of the request withdraws whatever else was under review; one withdrawn while the witness is asked
    // shows nothing of its late answer.
    await g.page.fill('#proof-code', a.identity)
    await g.page.click('#proof-review')
    await g.page.waitForSelector('#proof-panel:not([hidden])')
    const asked = await holdNext(g.page, `**${path}`)
    await g.page.click('#rescue-review')
    const go = await asked()
    assert.equal(await g.page.isHidden('#proof-panel'), true)
    await g.page.fill('#rescue-card', '  ')
    await go()
    await idle(g.page)
    assert.deepEqual([await g.page.isHidden('#rescue-panel'), await g.page.textContent('#error')], [true, ''])
    await g.page.click('#rescue-review')
    await g.page.waitForSelector('#rescue-panel:not([hidden])')
    assert.equal(await g.page.textContent('#error'), '')
    assert.equal(await g.page.textContent('#rescue-identity'), a.identity)
    assert.equal(await g.page.textContent('#rescue-roots'), nId)
    assert.equal(await g.page.textContent('#rescue-fingerprints'), print)
    assert.equal(await g.page.textContent('#rescue-recovery'), '1 of 1, after 3 days')
    assert.equal(await g.page.textContent('#rescue-wait'), '3 days after enough parties and the new passkey have signed, unless a passkey the identity has now cancels it')
    const gSigns = await signCount(g)
    // An edit while the passkey is signing withdraws it: the late signature is sent nowhere.
    const sent = (await t.witnessGet(path)).memberships.length
    await slowPasskey(g.page)
    await g.page.click('#rescue-sign')
    await g.page.fill('#rescue-card', '')
    await g.page.waitForTimeout(1500)
    await idle(g.page)
    assert.equal(await signCount(g), gSigns + 1, 'the passkey did sign')
    assert.deepEqual([(await t.witnessGet(path)).memberships.length, await g.page.textContent('#status')], [sent, ''])
    await promptPasskey(g.page)
    await g.page.click('#rescue-review')
    await g.page.waitForSelector('#rescue-panel:not([hidden])')
    t.refusing(true)
    await g.page.click('#rescue-sign')
    await errorIs(g.page, 'the witness refused the membership: test')
    assert.equal(await g.page.textContent('#status'), '', 'nothing said before is left standing')
    t.refusing(false)
    await g.page.click('#rescue-sign')
    await statusIs(g.page, 'Signed. The recovery is under notice once enough parties and the new passkey have signed.')
    assert.equal(await signCount(g), gSigns + 3)
    assert.equal((await current()).recovering, null, 'the new passkey has yet to sign')

    // The new passkey's kept signature is sent again, with its root record, which nobody else gave the witness.
    await n.page.bringToFront()
    await n.page.click('#cosign-retry')
    await n.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await n.page.textContent('#identity-id'), a.identity)
    assert.equal(await signCount(n), nSigns + 1, 'no second prompt')
    // Having signed, it asks the witness at once, and is told what it waits for.
    await n.page.waitForSelector('#recovery-notice:not([hidden])')
    assert.deepEqual([await n.page.isHidden('#notice-incoming'), await n.page.isHidden('#notice-own')], [false, true])
    await t.svc.tick()
    const noticed = await current()
    assert.equal(noticed.recovering.record, R.id)
    // It is told what it waits for, and offered no cancel; the owner's passkey is offered one.
    await n.page.reload()
    await n.page.waitForSelector('#recovery-notice:not([hidden])')
    assert.deepEqual([await n.page.isHidden('#notice-incoming'), await n.page.isHidden('#notice-own')], [false, true])
    await t.page.bringToFront()
    await t.page.reload()
    await t.page.waitForSelector('#recovery-notice:not([hidden])')
    assert.deepEqual([await t.page.isHidden('#notice-incoming'), await t.page.isHidden('#notice-own')], [true, false])
    assert.equal(await t.page.textContent('#notice-record'), R.id)

    // Uncancelled for the wait, and then the contest window: the identity is the new passkey's, which authorises a worker.
    t.advance(MIN + 1)
    await t.svc.tick()
    t.advance(61)
    await t.svc.tick()
    const after = await current()
    assert.deepEqual([after.membership, after.roots, after.authority, after.recovering], [R.id, [nId], [nId], null])
    await n.page.bringToFront()
    await n.page.reload()
    await n.page.waitForSelector('#identity:not([hidden])')
    await idle(n.page)
    assert.equal(await n.page.isHidden('#recovery-notice'), true)
    await authorise(n.page)
    await n.page.waitForSelector('#review-panel:not([hidden])')
    await n.page.click('#sign')
    await n.page.waitForSelector('#handoff:not([hidden])')
    assert.equal(envelope.open(envelope.wrap(JSON.parse(await n.page.inputValue('#handoff')).payload, { root: {}, subject: '0'.repeat(128) }), 'delegation').body.membership, R.id)
    assert.deepEqual(t.problems.filter((p) => !/status of (422 \(Unprocessable Entity\)|503 \(Service Unavailable\))$/.test(p)), [])
  } finally { await t.close() }
})

test('an application\'s request: it waits for an identity, fills the form and shows the review, is signed as anything typed is, and is answered at its own address', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const request = { v: 1, agent: 'drive', subject: SUBJECT, aud: 'https://node.example', scopes: ['store.ref', 'store.blob'], days: 3, return: 'https://app.example/drive/?a=1', state: 'S-1' }
    const link = (r) => t.site.origin + '/id/#muid-request=' + (typeof r === 'string' ? r : Buffer.from(JSON.stringify(r)).toString('base64url'))
    // The application's own page, stood in for; the id page's count of what it ran is taken as it leaves.
    const arrivals = []
    await t.context.route('https://app.example/**', async (route) => {
      await t.collect()
      arrivals.push(route.request().url())
      await route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>app</title>' })
    })
    const arrive = async (r) => { await t.page.goto('about:blank'); await t.page.goto(link(r)) }
    const shown = (ids) => Promise.all(ids.map((id) => t.page.isHidden('#' + id)))
    const fields = () => Promise.all(['agent', 'subject', 'aud', 'scopes', 'days'].map((id) => t.page.inputValue('#' + id)))

    // With no identity yet: the request waits, said beside the button that makes one, and nothing of it is shown.
    await arrive(request)
    await t.page.waitForSelector('#create:not([hidden])')
    assert.deepEqual(await shown(['request-waiting', 'request']), [false, true])
    assert.equal(await t.page.textContent('#error'), '')
    const r = await createIdentity(t.page)
    const root = rootModule.checkRoot(r.text, { rpId }).id
    // With one: who asked, by the origin of its return address, its request in the form, and the review of it shown
    // without being asked for: the fields of the payload that would be signed. Nothing is signed by arriving.
    const reviewShows = async (days) => {
      await t.page.waitForSelector('#review-panel:not([hidden])')
      assert.deepEqual([await t.page.textContent('#show-agent'), await t.page.textContent('#show-aud'), await t.page.textContent('#show-scopes'), await t.page.textContent('#show-subject')],
        ['drive', 'https://node.example', 'store.blob store.ref', SUBJECT])
      assert.equal(Math.abs(Date.parse(await t.page.textContent('#show-exp')) / 1000 - (Date.now() / 1000 + days * 86_400)) < 120, true, `${days} days`)
    }
    await reviewShows(3)
    assert.deepEqual(await shown(['request-waiting', 'request', 'request-unread', 'handoff']), [true, false, true, true])
    assert.equal(await t.page.textContent('#request-from'), 'https://app.example')
    assert.deepEqual(await fields(), ['drive', SUBJECT, 'https://node.example', 'store.ref store.blob', '3'])
    assert.equal(await t.page.textContent('#error'), '')
    const signs = await signCount(t)
    // Loaded again with its fragment, it is the request again, and reviewed again.
    await t.page.fill('#days', '2')
    await t.page.reload()
    await reviewShows(3)
    assert.deepEqual(await fields(), ['drive', SUBJECT, 'https://node.example', 'store.ref store.blob', '3'])
    // Filled and reviewed once: what the person then changes stays changed and withdraws the review, as any edit
    // does, and nothing fills or reviews it again, whatever the page shows again.
    await t.page.fill('#days', '2')
    assert.equal(await t.page.isHidden('#review-panel'), true)
    await change(t.page, 'workers', { rev: 1, workers: [] })
    await idle(t.page)
    assert.deepEqual([await t.page.inputValue('#days'), await t.page.isHidden('#review-panel')], ['2', true])
    await t.page.click('#review')
    await reviewShows(2)
    assert.equal(await signCount(t), signs)
    assert.deepEqual(arrivals, [])
    // Signed: the person is sent to the return address as given, with the state and the hand-off in its fragment.
    await t.page.click('#sign')
    await t.page.waitForURL((u) => u.origin === 'https://app.example')
    assert.equal(await signCount(t), signs + 1)
    assert.equal(arrivals.length, 1)
    const at = t.page.url()
    assert.equal(at.startsWith('https://app.example/drive/?a=1#muid='), true, at)
    const back = JSON.parse(Buffer.from(at.split('#muid=')[1], 'base64url').toString('utf8'))
    assert.deepEqual(Object.keys(back), ['v', 'state', 'handOff'])
    assert.deepEqual([back.v, back.state, typeof back.handOff], [1, 'S-1', 'string'])
    const h = JSON.parse(back.handOff)
    const d = envelope.open(envelope.wrap(h.payload, { root: h.root, subject: '0'.repeat(128) }), 'delegation')
    const now = Math.floor(Date.now() / 1000)
    assert.deepEqual(JSON.parse(JSON.stringify({ ...d.body, nbf: 0, exp: 0 })), { agent: 'drive', aud: 'https://node.example', exp: 0, identity: r.identity, membership: r.identity, nbf: 0, root, scopes: ['store.blob', 'store.ref'], subject: SUBJECT })
    assert.equal(Math.abs(d.body.exp - (now + 2 * 86_400)) < 120, true, 'for the two days the person chose')
    // The worker countersigns what came back, and the core accepts it.
    const consent = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(d.id, 'hex')]), WORKER))
    const c = delegationModule.checkDelegation(envelope.wrap(h.payload, { root: h.root, subject: consent }), { rootKey: rootModule.checkRoot(r.text, { rpId }).key, rpId, origin: t.site.origin, now, skew: 60, maxLifetime: 2_592_000 })
    assert.equal(c.ok, true, JSON.stringify(c))

    // A request for one key and another key authorised: the application that asked is not answered, and the
    // hand-off is shown here as ever. (The worker is remembered, as any authorised here.)
    const OTHER = hex(ed25519.getPublicKey(Uint8Array.from({ length: 32 }, (_, i) => 31 + i)))
    await arrive({ ...request, state: 'S-2' })
    await reviewShows(3)
    assert.equal(await t.page.locator('#workers li').count(), 1)
    await t.page.fill('#subject', OTHER)
    await t.page.fill('#agent', 'other')
    await t.page.click('#review')
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    await idle(t.page)
    assert.equal(new URL(t.page.url()).origin, t.site.origin)
    assert.equal(arrivals.length, 1)
    // The same key again, by a request with another state and a return address that is only a path: answered there.
    await arrive({ ...request, state: 'S-3', return: 'https://app.example/' })
    await reviewShows(3)
    await t.page.click('#sign')
    await t.page.waitForURL((u) => u.origin === 'https://app.example')
    assert.equal(t.page.url().startsWith('https://app.example/#muid='), true)
    assert.equal(JSON.parse(Buffer.from(t.page.url().split('#muid=')[1], 'base64url').toString('utf8')).state, 'S-3')

    // A request the page cannot read: said, nothing filled, and the page otherwise as it is without one.
    await arrive('x')
    await t.page.waitForSelector('#identity:not([hidden])')
    await idle(t.page)
    assert.deepEqual(await shown(['request-unread', 'request-waiting', 'request', 'authorise', 'review-panel']), [false, true, true, false, true])
    assert.deepEqual(await fields(), ['', '', '', '', '7'])
    // It stays said, whatever is done next on the page.
    await t.page.click('#review')
    await errorShown(t.page)
    assert.equal(await t.page.isHidden('#request-unread'), false)
    // No request: nothing of one is shown, and a worker authorised is handed over here.
    await t.page.goto('about:blank')
    await t.page.goto(t.site.origin + '/id/')
    await t.page.waitForSelector('#identity:not([hidden])')
    await idle(t.page)
    assert.deepEqual([...(await shown(['request-waiting', 'request', 'request-unread'])), await t.page.textContent('#error')], [true, true, true, ''])
    await authorise(t.page, { agent: 'drive', subject: SUBJECT })
    await t.page.waitForSelector('#review-panel:not([hidden])')
    await t.page.click('#sign')
    await t.page.waitForSelector('#handoff:not([hidden])')
    await idle(t.page)
    assert.equal(new URL(t.page.url()).origin, t.site.origin)
    // A passkey that is joining authorises nothing, and is shown no request; without an identity and without a
    // request, nothing waits.
    const j = await t.device()
    assert.deepEqual([await j.page.isHidden('#request-waiting'), await j.page.isHidden('#request')], [true, true])
    await j.page.goto('about:blank')
    await j.page.goto(link(request))
    await j.page.waitForSelector('#create:not([hidden])')
    await j.page.click('#join-button')
    await j.page.waitForSelector('#joining:not([hidden])')
    assert.deepEqual([await j.page.isHidden('#request-waiting'), await j.page.isHidden('#request')], [true, true])
    // An identity the witness does not yet know (it could not be reached): the request is in the form, and is
    // reviewed only once the identity is registered, when the review can be made.
    const k = await t.device()
    await k.page.goto('about:blank')
    await k.page.goto(link(request))
    await k.page.waitForSelector('#create:not([hidden])')
    t.outage('down')
    await k.page.fill('#name', 'late')
    await k.page.click('#create-button')
    await k.page.waitForSelector('#pending:not([hidden])')
    await errorShown(k.page)
    await idle(k.page)
    assert.deepEqual([await k.page.isHidden('#request'), await k.page.inputValue('#subject'), await k.page.isHidden('#review-panel')], [false, SUBJECT, true])
    assert.doesNotMatch(await k.page.textContent('#error'), /holds no record/, 'no review was tried')
    t.outage()
    await k.page.click('#register-retry')
    await k.page.waitForSelector('#review-panel:not([hidden])')
    assert.equal(await k.page.textContent('#show-subject'), SUBJECT)
    // An unreadable request with no identity: said before one is made, and after.
    const u = await t.device()
    await u.page.goto('about:blank')
    await u.page.goto(link('x'))
    await u.page.waitForSelector('#create:not([hidden])')
    assert.deepEqual([await u.page.isHidden('#request-unread'), await u.page.isHidden('#request-waiting')], [false, true])
    await createIdentity(u.page)
    await idle(u.page)
    assert.deepEqual([await u.page.isHidden('#request-unread'), await u.page.isHidden('#request'), await u.page.isHidden('#review-panel')], [false, true, true])
    assert.deepEqual(t.problems.filter((p) => !/status of 503/.test(p)), [])
  } finally { await t.close() }
})

test('an identity opened with a passkey this device has: only the identity\'s own, by the witness\'s records, and then used as one made here', { timeout: 180_000 }, async () => {
  const t = await open()
  try {
    const rpId = 'localhost'
    const a = await createIdentity(t.page)
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    // Another device to which the passkey has synced: the same credential, none of the page's storage.
    const b = await t.device()
    await b.cdp.send('WebAuthn.addCredential', { authenticatorId: b.authenticatorId, credential: credentials[0] })
    await b.page.waitForSelector('#create:not([hidden])')
    // An id that is none is refused before the passkey is asked.
    const before = await signCount(b)
    await b.page.fill('#open-identity', 'x')
    await b.page.click('#open-button')
    await errorIs(b.page, 'a record id is 64 lowercase hex digits')
    assert.equal(await signCount(b), before)
    // An identity the witness does not know: said, and nothing kept.
    await b.page.fill('#open-identity', 'ab'.repeat(32))
    await b.page.click('#open-button')
    await errorIs(b.page, 'the witness holds no record of this identity')
    assert.equal(await held(b.page, 'root'), null)
    // Its own: opened, kept as a registered root of its own identity, with the credential the platform used.
    await b.page.fill('#open-identity', ` ${a.identity} `)
    await b.page.click('#open-button')
    await b.page.waitForSelector('#identity:not([hidden])')
    await statusIs(b.page, 'Opened with your passkey.')
    assert.equal(await b.page.textContent('#identity-id'), a.identity)
    const kept = await held(b.page, 'root')
    assert.deepEqual([kept.text, kept.identity, kept.registered, kept.joining, kept.credential], [a.text, a.identity, true, false, credentials[0].credentialId.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')])
    assert.equal(await b.page.isHidden('#pending'), true, 'nothing to register')
    assert.equal((await t.witnessGet(`/v1/identities/${a.identity}/records`)).roots.length, 1, 'the same root: nothing was added')
    // And it acts for the identity as on the device that made it: a worker authorised there verifies.
    await authorise(b.page)
    await b.page.waitForSelector('#review-panel:not([hidden])')
    await b.page.click('#sign')
    await b.page.waitForSelector('#handoff:not([hidden])')
    const h = JSON.parse(await b.page.inputValue('#handoff'))
    const d = envelope.open(envelope.wrap(h.payload, { root: h.root, subject: '0'.repeat(128) }), 'delegation')
    const consent = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(d.id, 'hex')]), WORKER))
    const c = delegationModule.checkDelegation(envelope.wrap(h.payload, { root: h.root, subject: consent }), { rootKey: rootModule.checkRoot(a.text, { rpId }).key, rpId, origin: t.site.origin, now: Math.floor(Date.now() / 1000), skew: 60, maxLifetime: 2_592_000 })
    assert.equal(c.ok, true, JSON.stringify(c))

    // A device whose passkey is another identity's opens nothing of this one, and keeps nothing.
    const e = await t.device()
    const mine = await createIdentity(e.page)
    await drop(e.page, 'root')
    await e.page.reload()
    await e.page.waitForSelector('#create:not([hidden])')
    await e.page.fill('#open-identity', a.identity)
    await e.page.click('#open-button')
    await errorIs(e.page, "that passkey is not one of this identity's")
    assert.equal(await held(e.page, 'root'), null)
    assert.equal(await e.page.isHidden('#create'), false)
    // Its own identity it opens again.
    await e.page.fill('#open-identity', mine.identity)
    await e.page.click('#open-button')
    await e.page.waitForSelector('#identity:not([hidden])')
    assert.equal(await e.page.textContent('#identity-id'), mine.identity)
    // A passkey refused (no user verification) is said, and nothing is kept.
    const f = await t.device()
    await f.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: f.authenticatorId })
    const { authenticatorId } = await f.cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: false, automaticPresenceSimulation: true } })
    await f.cdp.send('WebAuthn.addCredential', { authenticatorId, credential: credentials[0] })
    await f.page.fill('#open-identity', a.identity)
    await f.page.click('#open-button')
    await errorIs(f.page, 'The passkey request was cancelled.')
    assert.equal(await held(f.page, 'root'), null)
    assert.deepEqual(t.problems.filter((p) => !/status of 404/.test(p)), [])
  } finally { await t.close() }
})

test('histories: two tabs, steps drawn at random, each judged by what the model states of every state', { timeout: 3_600_000 }, async () => {
  const t = await open({ init: HOLD_STORAGE })
  try {
    await createIdentity(t.page)
    // The second tab has the same passkey: its own virtual authenticator, given the first one's credential.
    const second = await t.tab(t.context)
    const cdp = await t.context.newCDPSession(second)
    await cdp.send('WebAuthn.enable')
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
    const { credentials } = await t.cdp.send('WebAuthn.getCredentials', { authenticatorId: t.authenticatorId })
    await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: credentials[0] })
    const pages = [t.page, second]
    const storage = async () => (await held(t.page, 'workers')) ?? { rev: 0, workers: [] }
    const listed = (page) => page.$$eval('#workers li', (lis) => lis.map((li) => {
      const [, agent, aud] = /^ (.*) at (\S+): /.exec(li.querySelector('label').textContent)
      return { agent, aud, subject: li.querySelector('code').textContent, ticked: li.querySelector('input').checked }
    }))
    // A step has ended when what it would show is shown, or an error is, or (pressed for a review since withdrawn,
    // which is silence) the review's panel is gone.
    const settled = (page, shown, panel = shown) => page.waitForFunction(([shown, panel]) => !document.getElementById(shown).hidden || document.getElementById('error').textContent !== '' || document.getElementById(panel).hidden, [shown, panel])
    let signed = 0
    // Under mutation testing and the twins a test has 60 s whatever count FC_RUNS sets: histories drawn after 30 s
    // are not run.
    const stop = performance.now() + 30_000

    await fc.assert(fc.asyncProperty(commands, fc.tuple(fc.boolean(), fc.boolean()), async (history, deaf) => {
      if (FAIL_FAST && performance.now() > stop) return
      // Each history starts from nothing remembered, both tabs loaded afresh, each hearing or deaf as drawn.
      await change(t.page, 'workers', null)
      for (const page of pages) { await page.reload(); await page.waitForSelector('#authorise:not([hidden])') }
      const tabs = pages.map((page, n) => ({ page, deaf: deaf[n], current: true, review: null }))
      for (const tab of tabs) if (tab.deaf) await tab.page.evaluate(() => { globalThis.holdStorage = true })
      let commits = 0
      const say = (i, c, what) => `step ${i} ${JSON.stringify(c)}: ${what}`
      for (const [i, c] of history.entries()) {
        const tab = tabs[c.tab]
        const { page } = tab
        // An error left by an earlier step is not this step's.
        await page.evaluate(() => { document.getElementById('error').textContent = '' })
        const before = await storage()
        // What storage must hold after the step: as it was, unless the step says otherwise.
        let expected = before.workers
        let committed = false
        // A review this tab made while up to date, nothing committed and no notice heard since, is honoured.
        const due = (r) => r.current && r.commits === commits && !r.told
        if (c.do === 'review') {
          const w = { agent: HISTORY_AGENTS[c.agent], aud: HISTORY_AUDS[c.aud], subject: workerPub(c.key) }
          await authorise(page, { ...w, scopes: 'post' })
          await page.waitForFunction(() => !document.getElementById('review-panel').hidden || document.getElementById('error').textContent !== '')
          const shown = !(await page.isHidden('#review-panel'))
          tab.review = shown ? { kind: 'worker', w, commits, current: tab.current, told: false, retires: await page.textContent('#show-retires') } : null
          assert.equal(shown, true, say(i, c, `a review is shown (${await page.textContent('#error')})`))
        } else if (c.do === 'sign' && tab.review?.kind === 'worker') {
          const r = tab.review
          // A review withdrawn by a notice has no button to press: that is a refusal, and judged as one.
          const open = !(await page.isHidden('#review-panel'))
          if (open) { await page.click('#sign'); await settled(page, 'handoff', 'review-panel') }
          const handed = open && !(await page.isHidden('#handoff'))
          if (handed) {
            assert.ok(r.current && r.commits === commits, say(i, c, 'handed over though a change was committed since the state it was reviewed against (ReviewedStateIsCurrent)'))
            const retired = before.workers.filter((x) => x.agent === r.w.agent && x.subject !== r.w.subject).map((x) => x.subject)
            for (const k of [1, 2].map(workerPub)) assert.equal(r.retires.includes(k), retired.includes(k), say(i, c, `the review said what it retires (ShownIsSaved): ${r.retires}`))
            expected = [...before.workers.filter((x) => !(x.agent === r.w.agent && (x.subject !== r.w.subject || x.aud === r.w.aud))), r.w]
            committed = true
            tab.current = true
            signed++
          } else {
            assert.equal(due(r), false, say(i, c, `a review that nothing made stale was refused: ${await page.textContent('#error')}`))
            tab.review = null
            if (open) tab.current = true // pressed, it read storage to find the change
          }
        } else if (c.do === 'forget') {
          const rows = await listed(page)
          if (rows.length > 0) {
            const row = rows[c.n % rows.length]
            await page.locator('#workers button').nth(c.n % rows.length).click()
            // The page lists what storage holds once the change is made: the row is no longer listed.
            await page.waitForFunction((gone) => ![...document.querySelectorAll('#workers code')].some((c) => c.textContent === gone[2] && c.closest('li').querySelector('label').textContent.startsWith(` ${gone[0]} at ${gone[1]}: `)) || document.getElementById('error').textContent !== '', [row.agent, row.aud, row.subject])
            expected = before.workers.filter((x) => rowOf(x) !== rowOf(row))
            committed = true
            tab.review = null
            tab.current = true
          }
        } else if (c.do === 'renew' && !(await page.isHidden('#renew'))) {
          const rows = (await listed(page)).filter((x) => x.ticked)
          await page.click('#renew-review')
          await page.waitForFunction(() => !document.getElementById('renew-panel').hidden || document.getElementById('error').textContent !== '')
          const shown = !(await page.isHidden('#renew-panel'))
          tab.review = shown ? { kind: 'renew', rows, commits, current: tab.current, told: false } : null
          if (rows.length > 0) assert.equal(shown, true, say(i, c, `a renewal is shown (${await page.textContent('#error')})`))
        } else if (c.do === 'renew-sign' && tab.review?.kind === 'renew') {
          const r = tab.review
          const open = !(await page.isHidden('#renew-panel'))
          if (open) { await page.click('#renew-sign'); await settled(page, 'renew-handoffs', 'renew-panel') }
          const handed = open && !(await page.isHidden('#renew-handoffs'))
          if (handed) {
            assert.ok(r.current && r.commits === commits, say(i, c, 'renewed though a change was committed since the state it was reviewed against (ReviewedStateIsCurrent)'))
            assert.equal(await page.locator('#renew-handoffs textarea').count(), r.rows.length, say(i, c, 'one hand-off for each worker reviewed'))
            for (const x of r.rows) assert.ok(before.workers.some((y) => rowOf(y) === rowOf(x)), say(i, c, 'each worker renewed is stored'))
            tab.review = null
          } else {
            assert.equal(due(r), false, say(i, c, `a renewal that nothing made stale was refused: ${await page.textContent('#error')}`))
            tab.review = null
            if (open) tab.current = true
          }
        } else if (c.do === 'untick') {
          const boxes = page.locator('#workers input')
          const n = await boxes.count()
          if (n > 0) { await boxes.nth(c.n % n).click(); tab.review = null }
        } else if (c.do === 'reload') {
          await page.reload()
          await page.waitForSelector('#authorise:not([hidden])')
          Object.assign(tab, { deaf: false, current: true, review: null })
        } else if (c.do === 'deafen') {
          await page.evaluate(() => { globalThis.holdStorage = true })
          tab.deaf = true
        } else if (c.do === 'hear') {
          const late = await page.evaluate(() => { globalThis.holdStorage = false; const held = globalThis.heldStorage.splice(0); for (const f of held) f(); return held.length })
          tab.deaf = false
          if (late > 0 && tab.review !== null) tab.review.told = true
        }

        const after = await storage()
        assert.deepEqual(after.workers.map(rowOf), expected.map(rowOf), say(i, c, 'storage holds exactly this step\'s change (NoLostUpdate, NoResurrection)'))
        assert.equal(after.rev, before.rev + (committed ? 1 : 0), say(i, c, 'the count is one more with a change, and only then'))
        for (const x of after.workers) assert.equal(after.workers.filter((y) => y.agent === x.agent && y.subject !== x.subject).length, 0, say(i, c, 'one key for each agent (OneKeyPerAgent)'))
        if (c.do === 'sign' && committed) {
          assert.ok(after.workers.some((x) => rowOf(x) === rowOf(tab.review.w)), say(i, c, 'handed over with its row stored (SavedBeforeHandover)'))
          tab.review = null
        }
        if (committed) {
          commits++
          // Every other tab is sent a notice: one that hears is told, and what it had open is withdrawn.
          for (const other of tabs) if (other !== tab) { if (other.deaf) other.current = false; else if (other.review !== null) other.review.told = true }
        }
        // A tab that hears lists what storage holds (ViewHonest); so does one that has just read it.
        for (const x of tabs) {
          if (!x.deaf || x.current) {
            const want = after.workers.map(rowOf)
            await x.page.waitForFunction((want) => JSON.stringify([...document.querySelectorAll('#workers li')].map((li) => { const m = /^ (.*) at (\S+): /.exec(li.querySelector('label').textContent); return JSON.stringify([m[1], m[2], li.querySelector('code').textContent]) })) === JSON.stringify(want), want)
              .catch(() => assert.fail(say(i, c, `tab ${tabs.indexOf(x)} lists what storage holds (ViewHonest)`)))
            if (!x.deaf) x.current = true
          }
        }
      }
    }), { numRuns: runs(10), endOnFailure: true, ...(process.env.FC_SEED === undefined ? {} : { seed: Number(process.env.FC_SEED) }) })
    assert.ok(signed > 0, 'some worker was saved: the histories reach the page\'s changes')
    assert.deepEqual(t.problems, [])
  } finally {
    await t.close()
  }
})
