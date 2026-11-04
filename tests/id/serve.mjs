// Serves the id page as a deployment would lay it out: /id/ (or a broken twin's directory), /src/, and the noble
// packages under /node_modules/@noble/. Nothing else.
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dir as idDir } from './impl.mjs'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' }
const MOUNTS = [['/id/', fileURLToPath(idDir)], ['/src/', join(ROOT, 'src/')], ['/node_modules/@noble/', join(ROOT, 'node_modules/@noble/')]]

export function serve () {
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://x').pathname)
    const m = MOUNTS.find(([p]) => path.startsWith(p))
    const rel = m && normalize(path.slice(m[0].length) || 'index.html')
    if (!m || rel.startsWith('..')) { res.writeHead(404).end(); return }
    try {
      const body = await readFile(join(m[1], rel))
      res.writeHead(200, { 'content-type': TYPES[rel.slice(rel.lastIndexOf('.'))] ?? 'application/octet-stream', 'x-frame-options': 'DENY' }).end(body)
    } catch { res.writeHead(404).end() }
  })
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ origin: `http://localhost:${server.address().port}`, close: () => server.close() })))
}
