// The runnable id origin (deploy/id-origin.mjs): the page with its configuration, what the page imports, and the
// witness service with holdings and a key that outlast the process; nothing else is served.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { configuration, start } from '../../deploy/id-origin.mjs'
import { envelope, root as rootModule, verifier as verifierModule } from '../impl.mjs'
import { KEY, ORIGIN } from '../assertion/helpers.mjs'
import { IDENTITY, BASE, M2, signed, rootText } from '../witness/fixtures.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const dir = () => mkdtempSync(join(tmpdir(), 'muid-id-origin-'))
const quiet = { log: () => {} }
const local = (data, more = {}) => configuration({ MUID_ORIGIN: 'http://localhost:8080', MUID_DATA: data, MUID_PORT: '0', ...more })
const meta = (html, name) => new RegExp(`<meta name="${name}" content="([^"]*)">`).exec(html)[1].replaceAll('&quot;', '"').replaceAll('&amp;', '&')

test('the configuration: an origin and a data directory are required, and every value is checked', () => {
  assert.deepEqual(configuration({ MUID_ORIGIN: 'https://id.example.org', MUID_DATA: '/d' }),
    { origin: 'https://id.example.org', rpId: 'id.example.org', data: '/d', port: 8080, host: '127.0.0.1', logUrl: undefined, contestWindow: 259_200, tick: 60 })
  assert.deepEqual(configuration({ MUID_ORIGIN: 'https://id.example.org', MUID_DATA: '/d', MUID_RP_ID: 'example.org', MUID_PORT: '9000', MUID_HOST: '::1', MUID_LOG_URL: 'http://127.0.0.1:2025/', MUID_CONTEST_WINDOW: '60', MUID_TICK: '5' }),
    { origin: 'https://id.example.org', rpId: 'example.org', data: '/d', port: 9000, host: '::1', logUrl: 'http://127.0.0.1:2025/', contestWindow: 60, tick: 5 })
  assert.equal(configuration({ MUID_ORIGIN: 'http://localhost:8080', MUID_DATA: '/d' }).rpId, 'localhost')
  const refused = (env, message) => assert.throws(() => configuration({ MUID_ORIGIN: 'https://id.example.org', MUID_DATA: '/d', ...env }), { message }, JSON.stringify(env))
  refused({ MUID_ORIGIN: undefined }, 'MUID_ORIGIN is required')
  refused({ MUID_ORIGIN: '' }, 'MUID_ORIGIN is required')
  refused({ MUID_DATA: undefined }, 'MUID_DATA is required')
  for (const origin of ['id.example.org', 'https://id.example.org/', 'https://id.example.org/id/', 'HTTPS://id.example.org', 'https://id.example.org:443', 'http://id.example.org', 'ftp://localhost']) {
    refused({ MUID_ORIGIN: origin }, /^MUID_ORIGIN must be an origin, as https:\/\/id\.example\.org/)
  }
  for (const rp of ['other.org', 'd.example.org', 'ample.org', 'org.evil']) refused({ MUID_RP_ID: rp }, "MUID_RP_ID must be the origin's host or a parent domain of it")
  for (const port of ['x', '-1', '65536', '80.5']) refused({ MUID_PORT: port }, 'MUID_PORT must be a port')
  for (const n of ['0', 'x', '1.5', '-3']) {
    refused({ MUID_CONTEST_WINDOW: n }, 'MUID_CONTEST_WINDOW must be a whole number of seconds, at least 1')
    refused({ MUID_TICK: n }, 'MUID_TICK must be a whole number of seconds, at least 1')
  }
})

test('the page is served with its configuration, with what it imports, unframeable; nothing else is', async () => {
  const data = dir()
  const said = []
  const s = await start(local(data), { log: (line) => said.push(line) })
  try {
    assert.match(s.url, /^http:\/\/127\.0\.0\.1:\d+$/)
    const page = await fetch(s.url + '/id/')
    assert.equal(page.status, 200)
    assert.equal(page.headers.get('content-type'), 'text/html; charset=utf-8')
    assert.deepEqual([page.headers.get('x-frame-options'), page.headers.get('content-security-policy'), page.headers.get('x-content-type-options')], ['DENY', "frame-ancestors 'none'", 'nosniff'])
    const html = await page.text()
    assert.deepEqual([meta(html, 'muid-rp-id'), meta(html, 'muid-origin'), meta(html, 'muid-witness')], ['localhost', 'http://localhost:8080', '/witness/'])
    assert.deepEqual(JSON.parse(meta(html, 'muid-witness-keys')), s.witnessKeys)
    assert.equal(s.witnessKeys.length, 1)
    assert.match(s.witnessKeys[0].key, /^[0-9a-f]{64}$/)
    assert.equal(await (await fetch(s.url + '/id/index.html')).text(), html)
    // The page's own Content-Security-Policy is the file's, untouched but for the three meta tags.
    assert.equal(html.replace(/<meta name="muid-(rp-id|origin|witness-keys)" content="[^"]*">/g, ''), readFileSync(new URL('../../id/index.html', import.meta.url), 'utf8').replace(/<meta name="muid-(rp-id|origin|witness-keys)" content="[^"]*">/g, ''))
    for (const [path, type] of [['/id/page.js', 'text/javascript'], ['/id/page.css', 'text/css'], ['/src/verifier.js', 'text/javascript'], ['/node_modules/@noble/curves/ed25519.js', 'text/javascript']]) {
      const r = await fetch(s.url + path)
      assert.deepEqual([r.status, r.headers.get('content-type')], [200, type], path)
      assert.equal(await r.text(), readFileSync(new URL('../..' + path, import.meta.url), 'utf8'), path)
    }
    const head = await fetch(s.url + '/id/page.js', { method: 'HEAD' })
    assert.deepEqual([head.status, await head.text()], [200, ''])
    const home = await fetch(s.url + '/', { redirect: 'manual' })
    assert.deepEqual([home.status, home.headers.get('location')], [302, '/id/'])
    for (const path of ['/package.json', '/witness', '/id/../package.json', '/id/%2e%2e/package.json', '/src/..%2fpackage.json', '/src/%2e%2e/deploy/id-origin.mjs', '/node_modules/@stryker-mutator/core/package.json',
      '/node_modules/@noble/curves/package.json', '/id/nothing.js', '/tests/impl.mjs', '/id/%00', '/deploy/id-origin.mjs']) {
      assert.equal((await fetch(s.url + path)).status, 404, path)
    }
    assert.equal((await fetch(s.url + '/id/%E0%A4%A')).status, 400, 'a path that is not UTF-8')
    assert.equal((await fetch(s.url + '/id/page.js', { method: 'POST', body: 'x' })).status, 404)
    assert.equal(said.some((line) => line.includes(s.witnessKeys[0].key)), true, 'the keys to pin are said at start')
    assert.equal(said.some((line) => line.includes('in memory')), true, 'and that the log is in memory')
  } finally { await s.close() }
})

test('the witness service: reached under /witness/, readable from any origin, its key and holdings kept across a restart', async () => {
  const data = dir()
  const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: 'localhost' }).payload)
  const identity = rootModule.identityOf(rootModule.checkRoot(rootText, { rpId: 'localhost' }).id)
  let s = await start(local(data), quiet)
  let keys
  try {
    keys = s.witnessKeys
    const registered = await fetch(s.url + '/witness/v1/records', { method: 'POST', body: JSON.stringify({ identity, type: 'root', text: rootText }) })
    assert.deepEqual([registered.status, registered.headers.get('access-control-allow-origin'), registered.headers.get('content-type'), registered.headers.get('cache-control')], [200, '*', 'application/json', 'no-store'])
    assert.equal((await registered.json()).ok, true)
    const head = await (await fetch(s.url + `/witness/v1/identities/${identity}/head`)).json()
    // The head verifies under the keys the page is given, for the configured rp ID and origin.
    const v = verifierModule.verifier({ rpId: 'localhost', origin: 'http://localhost:8080', audience: 'https://app.example', witnessKeys: keys, skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })
    const now = Math.floor(Date.now() / 1000)
    assert.equal(v.verifyHead(head.head, { now, scope: 'x', revoked: [] }).ok, true)
    const preflight = await fetch(s.url + '/witness/v1/delegations', { method: 'OPTIONS', headers: { origin: 'https://drive.example', 'access-control-request-method': 'POST' } })
    assert.deepEqual([preflight.status, preflight.headers.get('access-control-allow-origin'), preflight.headers.get('access-control-allow-methods')], [204, '*', 'GET, POST'])
    const unknown = await fetch(s.url + '/witness/v1/nothing')
    assert.deepEqual([unknown.status, unknown.headers.get('access-control-allow-origin'), await unknown.json()], [404, '*', { ok: false, reason: 'not-found' }])
    assert.deepEqual(await s.tick(), [], 'a pass with nothing due signs nothing')
    assert.equal(statSync(join(data, 'witness.key')).mode & 0o777, 0o600)
    assert.equal(hex(ed25519.getPublicKey(Buffer.from(readFileSync(join(data, 'witness.key'), 'utf8').trim(), 'hex'))), keys[0].key)
    // A second process on the same holdings is refused at once.
    await assert.rejects(start(local(data), quiet), { message: 'the holdings are held by another process' })
  } finally { await s.close() }
  s = await start(local(data), quiet)
  try {
    assert.deepEqual(s.witnessKeys, keys, 'the same key')
    const held = await (await fetch(s.url + `/witness/v1/identities/${identity}/records`)).json()
    assert.deepEqual(held.roots, [rootText], 'and what it held')
  } finally { await s.close() }
  // A key file that is no key stops the start, and is left as it is.
  writeFileSync(join(data, 'witness.key'), 'x\n')
  await assert.rejects(start(local(data), quiet), { message: /witness\.key is not a witness key$/ })
  assert.equal(readFileSync(join(data, 'witness.key'), 'utf8'), 'x\n')
})

test('the witness makes its pass by itself: a change settles once its window has passed', async () => {
  // The fixtures' identity: a root, and a change adding a second, signed by both.
  let now = BASE
  const s = await start(configuration({ MUID_ORIGIN: ORIGIN, MUID_DATA: dir(), MUID_PORT: '0', MUID_CONTEST_WINDOW: '60', MUID_TICK: '1' }), { clock: () => now, log: () => {} })
  try {
    const post = async (type, text) => assert.equal((await (await fetch(s.url + '/witness/v1/records', { method: 'POST', body: JSON.stringify({ identity: IDENTITY, type, text }) })).json()).ok, true, type)
    await post('root', rootText('a'))
    await post('membership', signed('membership', M2, 'a'))
    await post('root', rootText('b'))
    await post('membership', signed('membership', M2, 'b'))
    const held = async () => (await fetch(s.url + `/witness/v1/identities/${IDENTITY}/records`)).json()
    assert.equal((await held()).settlements.length, 0)
    now += 61
    for (let i = 0; i < 50 && (await held()).settlements.length === 0; i++) await new Promise((resolve) => setTimeout(resolve, 100))
    assert.equal((await held()).settlements.length, 1, 'signed by the witness\'s own pass, with nothing asked of it')
  } finally { await s.close() }
})
