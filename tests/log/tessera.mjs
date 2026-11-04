// Starts Tessera's POSIX server (log/go.mod, `go tool posix`) on a free local port with a fresh note key and an
// empty directory; resolves once it serves a checkpoint.
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { keyPair, b64 } from '../note/helpers.mjs'

const LOG_DIR = new URL('../../log/', import.meta.url).pathname

const freePort = () => new Promise((resolve) => {
  const s = createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)) })
})

export async function startLog (origin = 'log.test/muid') {
  const k = keyPair(origin, 1, randomBytes(1)[0])
  const [, id] = k.vkey.split('+')
  const privateKey = `PRIVATE+KEY+${origin}+${id}+${b64(Buffer.concat([Buffer.from([1]), Buffer.from(k.secret)]))}`
  const dir = mkdtempSync(join(tmpdir(), 'muid-log-'))
  const port = await freePort()
  const child = spawn('go', ['tool', 'posix', `--storage_dir=${dir}`, `--listen=127.0.0.1:${port}`], {
    cwd: LOG_DIR, env: { ...process.env, LOG_PRIVATE_KEY: privateKey, GOFLAGS: '-mod=readonly' }, stdio: ['ignore', 'ignore', 'pipe'],
  })
  let err = ''
  child.stderr.on('data', (d) => { err += d })
  const url = `http://127.0.0.1:${port}/`
  const stop = () => { child.kill(); rmSync(dir, { recursive: true, force: true }) }
  for (let i = 0; i < 600; i++) {
    if (child.exitCode !== null) throw new Error(`log exited: ${err}`)
    try {
      const r = await fetch(url + 'checkpoint')
      if (r.ok) return { url, vkey: k.vkey, origin, stop }
    } catch { /* not listening yet */ }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  stop()
  throw new Error(`log did not start: ${err}`)
}
