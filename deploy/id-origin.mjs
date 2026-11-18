#!/usr/bin/env node
// An id origin, runnable: the id page and its witness service behind one plain HTTP port, to sit behind a proxy
// that terminates TLS for the origin (a passkey works only over https, or at localhost). Not core, and not part of
// the package's stable surface: a deployment may equally serve id/ and the witness service by its own means.
//
//   MUID_ORIGIN=https://id.example.org MUID_DATA=/var/lib/muid node deploy/id-origin.mjs
//
//   MUID_ORIGIN          the exact origin the page is opened at (required). Passkeys made here are bound to its
//                        host for good: choose it before anyone makes an identity they mean to keep.
//   MUID_DATA            a directory this process alone uses (required): the witness's key (witness.key, made on
//                        the first run, readable by its owner only) and its holdings (holdings.sqlite).
//   MUID_RP_ID           the passkeys' rp ID; the origin's host unless given (a parent domain of it).
//   MUID_PORT, MUID_HOST where to listen; 8080 at 127.0.0.1 unless given.
//   MUID_LOG_URL         a transparency log to append to (log/cmd/muid-log). Without one the log is kept in
//                        memory and lost when the process ends: for a trial, and said at start.
//   MUID_CONTEST_WINDOW  seconds a membership change may be contested; three days unless given.
//   MUID_TICK            seconds between the witness's passes over its identities; 60 unless given.
//
// Served: /id/ (the page, its deployment configuration written into its meta tags), /src/ and
// /node_modules/@noble/ (what the page imports), and /witness/ (the service). The witness's answers are public and
// may be read from any origin, as a worker in another origin's page reads them. Nothing else is served.
import { createServer } from 'node:http'
import { readFile, mkdir, writeFile, chmod } from 'node:fs/promises'
import { realpathSync } from 'node:fs'
import { join, normalize, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { Readable } from 'node:stream'
import { randomBytes } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { witness } from '../witness/witness.js'
import { witnessService, memoryLog } from '../witness/service.js'
import { sqliteHoldings } from '../witness/holdings.js'
import { tesseraLog } from '../witness/log.js'

const hex = (b) => Buffer.from(b).toString('hex')
const HERE = (path) => fileURLToPath(new URL(path, import.meta.url))
// The two packages the page imports are found as Node finds them from this file: beside it in a checkout, in the
// parent's node_modules where this package is installed as a dependency.
const PACKAGE = (file) => dirname(fileURLToPath(import.meta.resolve(file))) + '/'
const MOUNTS = [['/id/', HERE('../id/')], ['/src/', HERE('../src/')],
  ['/node_modules/@noble/hashes/', PACKAGE('@noble/hashes/sha2.js')], ['/node_modules/@noble/curves/', PACKAGE('@noble/curves/ed25519.js')]]
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' }
const KEY_YEARS = 20
const attribute = (s) => s.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;')

// The witness's secret key, made on the first run and kept in `file`, which only its owner may read.
async function witnessSecret (file) {
  try {
    const text = (await readFile(file, 'utf8')).trim()
    if (!/^[0-9a-f]{64}$/.test(text)) throw new Error(`${file} is not a witness key`)
    return Buffer.from(text, 'hex')
  } catch (e) {
    if (e.code !== 'ENOENT') throw e
  }
  const secret = randomBytes(32)
  await writeFile(file, hex(secret) + '\n', { mode: 0o600, flag: 'wx' })
  await chmod(file, 0o600)
  return secret
}

// The configuration, read from an environment: every value checked before anything is opened.
export function configuration (env) {
  const need = (name) => { if (!env[name]) throw new Error(`${name} is required`); return env[name] }
  const seconds = (name, otherwise, least) => {
    const n = env[name] === undefined ? otherwise : Number(env[name])
    if (!Number.isSafeInteger(n) || n < least) throw new Error(`${name} must be a whole number of seconds, at least ${least}`)
    return n
  }
  let url
  try {
    url = new URL(need('MUID_ORIGIN'))
  } catch (e) {
    throw new Error(e.message === 'MUID_ORIGIN is required' ? e.message : 'MUID_ORIGIN must be an origin, as https://id.example.org')
  }
  if (url.origin !== env.MUID_ORIGIN || (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost'))) {
    throw new Error('MUID_ORIGIN must be an origin, as https://id.example.org (http only at localhost)')
  }
  const rpId = env.MUID_RP_ID ?? url.hostname
  if (url.hostname !== rpId && !url.hostname.endsWith('.' + rpId)) throw new Error("MUID_RP_ID must be the origin's host or a parent domain of it")
  const port = env.MUID_PORT === undefined ? 8080 : Number(env.MUID_PORT)
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new Error('MUID_PORT must be a port')
  return { origin: url.origin, rpId, data: need('MUID_DATA'), port, host: env.MUID_HOST ?? '127.0.0.1', logUrl: env.MUID_LOG_URL,
    contestWindow: seconds('MUID_CONTEST_WINDOW', 259_200, 1), tick: seconds('MUID_TICK', 60, 1) }
}

// Opens the data directory and starts listening. { url, witnessKeys, tick(), close() }; `clock` is for tests.
export async function start (config, { clock = () => Math.floor(Date.now() / 1000), log = console.log } = {}) {
  await mkdir(config.data, { recursive: true })
  const secret = await witnessSecret(join(config.data, 'witness.key'))
  const key = hex(ed25519.getPublicKey(secret))
  const witnessKeys = [{ key, nbf: 0, exp: Math.floor(Date.UTC(2026 + KEY_YEARS, 0, 1) / 1000) }]
  const holdings = sqliteHoldings(join(config.data, 'holdings.sqlite'))
  const service = witnessService({
    witness: witness({ rpId: config.rpId, origin: config.origin, witnessKeys, key, sign: (b) => hex(ed25519.sign(b, secret)), contestWindow: config.contestWindow, skew: 60, maxLifetime: 2_592_000 }),
    holdings,
    log: config.logUrl === undefined ? memoryLog() : tesseraLog({ url: config.logUrl }),
    clock,
    headInterval: 5
  })
  const page = (await readFile(join(MOUNTS[0][1], 'index.html'), 'utf8'))
    .replace('<meta name="muid-rp-id" content="">', `<meta name="muid-rp-id" content="${attribute(config.rpId)}">`)
    .replace('<meta name="muid-origin" content="">', `<meta name="muid-origin" content="${attribute(config.origin)}">`)
    .replace('<meta name="muid-witness-keys" content="[]">', `<meta name="muid-witness-keys" content="${attribute(JSON.stringify(witnessKeys))}">`)
  if (!page.includes(`content="${attribute(config.origin)}"`) || !page.includes(attribute(key))) throw new Error('id/index.html has no place for its configuration')
  // no-transform: a proxy in front must pass the page as it is (one that adds a script changes what the page's own
  // policy was written for, and is refused by it).
  const SECURITY = { 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' }
  const FRAMING = { 'x-frame-options': 'DENY', 'content-security-policy': "frame-ancestors 'none'" }
  const PUBLIC = { 'access-control-allow-origin': '*' }

  async function toWitness (req, res, path) {
    if (req.method === 'OPTIONS') { res.writeHead(204, { ...SECURITY, ...PUBLIC, 'access-control-allow-methods': 'GET, POST', 'access-control-max-age': '86400' }).end(); return }
    const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : Readable.toWeb(req)
    const r = await service.handle(new Request('http://witness' + path.slice('/witness'.length), { method: req.method, body, duplex: 'half' }))
    res.writeHead(r.status, { ...SECURITY, ...PUBLIC, 'content-type': 'application/json', 'cache-control': 'no-store, no-transform' }).end(Buffer.from(await r.arrayBuffer()))
  }
  async function toFile (req, res, path) {
    const m = MOUNTS.find(([prefix]) => path.startsWith(prefix))
    const rel = m && normalize(path.slice(m[0].length) || 'index.html')
    if ((req.method !== 'GET' && req.method !== 'HEAD') || !m || rel.startsWith('..') || rel.includes('\0')) { res.writeHead(404, SECURITY).end(); return }
    const type = TYPES[rel.slice(rel.lastIndexOf('.'))]
    if (type === undefined) { res.writeHead(404, SECURITY).end(); return }
    let body
    try {
      body = m[0] === '/id/' && rel === 'index.html' ? Buffer.from(page) : await readFile(join(m[1], rel))
    } catch { res.writeHead(404, SECURITY).end(); return }
    res.writeHead(200, { ...SECURITY, ...FRAMING, 'content-type': type, 'cache-control': 'no-cache, no-transform' }).end(req.method === 'HEAD' ? undefined : body)
  }
  const server = createServer((req, res) => {
    let path
    try {
      path = decodeURIComponent(new URL(req.url, 'http://x').pathname)
    } catch { res.writeHead(400, SECURITY).end(); return }
    const done = path === '/' ? Promise.resolve(res.writeHead(302, { ...SECURITY, location: '/id/' }).end())
      : path.startsWith('/witness/') ? toWitness(req, res, path) : toFile(req, res, path)
    done.catch(() => { if (!res.headersSent) res.writeHead(500, SECURITY); res.end() })
  })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.port, config.host, resolve) })
  // The witness's own pass: settlements once windows pass, notices, maturities. A pass that fails is tried again.
  const tick = () => service.tick().catch((e) => { log(`a pass failed and will be tried again: ${e.message}`) })
  const timer = setInterval(tick, config.tick * 1000)
  timer.unref()
  const url = `http://${config.host.includes(':') ? `[${config.host}]` : config.host}:${server.address().port}`
  log(`muid id origin ${config.origin} (rp ID ${config.rpId}) listening at ${url}`)
  log(`witness keys, for relying parties to pin: ${JSON.stringify(witnessKeys)}`)
  if (config.logUrl === undefined) log('no MUID_LOG_URL: the transparency log is in memory and ends with this process')
  return {
    url,
    witnessKeys,
    tick: () => service.tick(),
    close: () => new Promise((resolve) => { clearInterval(timer); server.close(() => { holdings.close?.(); resolve() }); server.closeAllConnections?.() })
  }
}

// Run as a program (by whatever path: a module's own URL is its real path, a command line's may go through links).
const program = () => { try { return pathToFileURL(realpathSync(process.argv[1])).href } catch { return undefined } }
if (import.meta.url === program()) {
  try {
    const running = await start(configuration(process.env))
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => running.close().then(() => process.exit(0)))
  } catch (e) {
    console.error(`muid id origin: ${e.message}`)
    process.exit(1)
  }
}
