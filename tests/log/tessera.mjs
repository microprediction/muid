// Starts the transparency log (log/cmd/muid-log: Tessera's POSIX server with a witness policy) on a free local port
// with a fresh note key and an empty directory, and, if asked, transparency-dev's omniwitness (pinned in log/go.mod)
// as its one cosigner, which the log's policy then requires. Resolves once the log serves a checkpoint.
import { spawn, execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { keyId, b64 } from '../note/helpers.mjs'

const LOG_DIR = new URL('../../log/', import.meta.url).pathname
const ENV = { ...process.env, GOFLAGS: '-mod=readonly' }
// The two programs, built once per process from the pinned module and run directly, so stopping them stops them.
const BIN = mkdtempSync(join(tmpdir(), 'muid-log-bin-'))
const built = new Map()
function binary (name, pkg) {
  if (!built.has(name)) {
    execFileSync('go', ['build', '-o', join(BIN, name), pkg], { cwd: LOG_DIR, env: ENV, stdio: ['ignore', 'ignore', 'inherit'] })
    built.set(name, join(BIN, name))
  }
  return built.get(name)
}
process.on('exit', () => rmSync(BIN, { recursive: true, force: true }))

const freePort = () => new Promise((resolve) => {
  const s = createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)) })
})
// A fresh note signing key in Go's format, its Ed25519 verifier key (0x01) and its cosignature verifier key (0x04).
function noteKey (name) {
  const secret = randomBytes(32)
  const pub = Buffer.from(ed25519.getPublicKey(secret))
  const vkeyOf = (type) => `${name}+${keyId(name, type, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([type]), pub]))}`
  const skey = `PRIVATE+KEY+${name}+${keyId(name, 1, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([1]), secret]))}`
  return { skey, vkey: vkeyOf(1), cosigner: vkeyOf(4) }
}

function start ([program, ...args], label) {
  const child = spawn(program, args, { env: ENV, stdio: ['ignore', 'ignore', 'pipe'] })
  let err = ''
  child.stderr.on('data', (d) => { err += d })
  return { child, err: () => `${label}: ${err}` }
}

async function until (ready, proc) {
  for (let i = 0; i < 1200; i++) {
    if (proc.child.exitCode !== null) throw new Error(`exited: ${proc.err()}`)
    try { if (await ready()) return } catch { /* not listening yet */ }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`did not start: ${proc.err()}`)
}

export async function startLog ({ origin = 'log.test/muid', witnessed = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'muid-log-'))
  const procs = []
  const stop = async () => {
    await Promise.all(procs.map((p) => p.child.exitCode !== null ? undefined : new Promise((resolve) => { p.child.once('exit', resolve); p.child.kill() })))
    rmSync(dir, { recursive: true, force: true })
  }
  try {
    const log = noteKey(origin)
    const port = await freePort()
    const url = `http://127.0.0.1:${port}/`
    const args = [binary('muid-log', './cmd/muid-log'), `--storage_dir=${join(dir, 'log')}`, `--listen=127.0.0.1:${port}`, `--private_key=${join(dir, 'log.key')}`]
    writeFileSync(join(dir, 'log.key'), log.skey)
    let cosigner
    if (witnessed) {
      const w = noteKey('witness.test/muid')
      cosigner = w.cosigner
      const wport = await freePort()
      writeFileSync(join(dir, 'witness.key'), w.skey)
      writeFileSync(join(dir, 'logs.yaml'), `Logs:\n  - Origin: ${origin}\n    URL: ${url}\n    PublicKey: ${log.vkey}\n`)
      const wp = start([binary('omniwitness', 'github.com/transparency-dev/witness/cmd/omniwitness'), `--listen=127.0.0.1:${wport}`, `--metrics_listen=127.0.0.1:${await freePort()}`,
        `--private_key_path=${join(dir, 'witness.key')}`, `--additional_logs=${join(dir, 'logs.yaml')}`], 'witness')
      procs.push(wp)
      await until(async () => (await fetch(`http://127.0.0.1:${wport}/add-checkpoint`, { method: 'POST', body: '' })).status < 500, wp)
      writeFileSync(join(dir, 'policy'), `witness w1 ${cosigner} http://127.0.0.1:${wport}/\nquorum w1\n`)
      args.push(`--witness_policy_file=${join(dir, 'policy')}`)
    }
    const lp = start(args, 'log')
    procs.push(lp)
    await until(async () => (await fetch(url + 'checkpoint')).ok, lp)
    return { url, vkey: log.vkey, origin, cosigner, stop }
  } catch (e) {
    await stop()
    throw e
  }
}
