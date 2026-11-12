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
  return { site, browser, ...first, device, tab, problems, collect, keys, clock, witnessGet, witnessPost, svc: real, refusing, outage, advance: (s) => { offset += s },
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
    if (mode === 'get') values.get(key).onsuccess = (e) => { if (e.target.result !== undefined) out = e.target.result.value }
    else if (mode === 'delete') values.delete(key)
    else values.put({ value }, key)
    tx.oncomplete = () => { opening.result.close(); resolve(out) }
    tx.onabort = () => reject(tx.error)
  }
}), [mode, key, value])
const held = (page, key) => direct(page, 'get', key)
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
    await t.page.waitForLoadState('networkidle')
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
      await fresh.page.waitForLoadState('networkidle')
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
    const a = await createIdentity(t.page)
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
    await b.page.waitForLoadState('networkidle')
    assert.deepEqual(posted, [], 'nothing is sent')
    assert.equal(await b.page.textContent('#error'), '', 'and nothing is tried')
    assert.deepEqual(await held(b.page, 'root'), other, 'and the root there is left as it was')
    // It becomes another while the witness is asked, and the tab is told: the other root is not marked.
    await change(b.page, 'root', mine)
    await b.page.waitForFunction((text) => document.getElementById('join-root').value === text, mine.text)
    await review()
    swap = true
    await b.page.click('#cosign-sign')
    await b.page.waitForFunction((text) => document.getElementById('join-root').value === text, other.text)
    await b.page.waitForLoadState('networkidle')
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
    const settled = async () => { release(); held = null; await t.page.waitForLoadState('networkidle'); await t.page.waitForTimeout(300) }
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
    await t.page.waitForLoadState('networkidle')
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
    const settled = async () => { release(); held = null; await t.page.waitForLoadState('networkidle'); await t.page.waitForTimeout(300) }
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
