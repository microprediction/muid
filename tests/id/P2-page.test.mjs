// The id page in Chrome, with a virtual authenticator (Chrome DevTools Protocol, WebAuthn domain): an identity is
// created, a worker authorised by one assertion, and what the page hands the worker, once the worker consents,
// verifies under the core — through the witness's head and the relying party's verifier.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ed25519 } from '@noble/curves/ed25519.js'
import { chromium } from 'playwright-core'
import { generateKeyPairSync } from 'node:crypto'
import { root as rootModule, delegation as delegationModule, assertion as assertionModule, envelope, verifier as verifierModule } from '../impl.mjs'
import { witness } from '../witness/impl.mjs'
import { serve } from './serve.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const WORKER = Uint8Array.from({ length: 32 }, (_, i) => 77 + i)
const SUBJECT = hex(ed25519.getPublicKey(WORKER))
const W = Uint8Array.from({ length: 32 }, (_, i) => 120 + i)
const WITNESS = hex(ed25519.getPublicKey(W))

async function open ({ init } = {}) {
  const site = await serve()
  const browser = await chromium.launch({ channel: 'chrome', headless: true })
  const context = await browser.newContext()
  // Under mutation testing, the mutant the runner activated is activated in the page too: Stryker's instrumented code
  // reads it from process.env in Node, which a page has not.
  const mutant = process.env.__STRYKER_ACTIVE_MUTANT__
  if (mutant !== undefined) await context.addInitScript((m) => { globalThis.__stryker__ = { activeMutant: m } }, mutant)
  if (init !== undefined) await context.addInitScript(init)
  const page = await context.newPage()
  const problems = []
  // Chrome warns that only ES256 is offered: deliberate (I6), and the only warning allowed.
  const ES256_ONLY = /^publicKey\.pubKeyCredParams is missing at least one of the default algorithm identifiers: ES256 and RS256\./
  page.on('console', (m) => { if ((m.type() === 'error' || m.type() === 'warning') && !ES256_ONLY.test(m.text())) problems.push(m.text()) })
  page.on('pageerror', (e) => problems.push(String(e)))
  const cdp = await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })
  await page.goto(site.origin + '/id/')
  // Under mutation testing's first run, the page's coverage is added to this process's, which the runner reads.
  const collect = async () => {
    const ns = globalThis.__stryker__
    const cov = ns === undefined ? undefined : await page.evaluate(() => globalThis.__stryker__?.mutantCoverage)
    if (cov === undefined) return
    ns.mutantCoverage ??= { static: {}, perTest: {} }
    for (const [id, n] of Object.entries(cov.static)) ns.mutantCoverage.static[id] = (ns.mutantCoverage.static[id] ?? 0) + n
  }
  return { site, browser, context, page, cdp, authenticatorId, problems, collect, close: async () => { await collect(); await browser.close(); site.close() } }
}

async function createIdentity (page, name = 'test') {
  await page.fill('#name', name)
  await page.click('#create-button')
  await page.waitForSelector('#identity:not([hidden])')
  return { text: await page.inputValue('#root-text'), identity: await page.textContent('#identity-id') }
}

async function authorise (page, { subject = SUBJECT, aud = 'https://app.example', scopes = 'post read', days = '1' } = {}) {
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
    await authorise(t.page, { subject: ` ${SUBJECT} `, aud: ' https://app.example ', scopes: ' post  read ' })
    await t.page.waitForSelector('#review-panel:not([hidden])')
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

    // The witness holds the root and signs a head; a relying party at the audience accepts the delegation.
    const sign = (bytes) => hex(ed25519.sign(bytes, W))
    const keys = [{ key: WITNESS, nbf: 0, exp: now + 86_400 }]
    const w = witness({ rpId, origin: t.site.origin, witnessKeys: keys, key: WITNESS, sign, contestWindow: 259_200, skew: 60, maxLifetime: 2_592_000 })
    const held = w.admit(w.empty(r.identity), 'root', r.text).held
    const head = w.head(held, now)
    const v = verifierModule.verifier({ rpId, origin: t.site.origin, audience: 'https://app.example', witnessKeys: keys, skew: 60,
      maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
    const accepted = v.verifyDelegation({ delegation: text, root: r.text, head }, { now, scope: 'post', revoked: [] })
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
    await authorise(t.page, { subject: 'x' })
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
  const t = await open()
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
