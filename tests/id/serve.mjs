// Serves the id page as a deployment would lay it out: /id/ (or a broken twin's directory), /src/, the noble
// packages under /node_modules/@noble/, and, given one, a witness service under /witness/. The deployment
// configuration (rp ID, origin, the witness's keys) is written into the page's meta tags. Nothing else.
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { join, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Readable } from 'node:stream'
import { dir as idDir } from './impl.mjs'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' }
const MOUNTS = [['/id/', fileURLToPath(idDir)], ['/src/', join(ROOT, 'src/')], ['/node_modules/@noble/', join(ROOT, 'node_modules/@noble/')]]

async function toWitness (svc, req, res, path) {
  const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : Readable.toWeb(req)
  const r = await svc.handle(new Request('http://witness' + path.slice('/witness'.length), { method: req.method, body, duplex: 'half' }))
  res.writeHead(r.status, { 'content-type': r.headers.get('content-type') ?? 'text/plain' }).end(Buffer.from(await r.arrayBuffer()))
}

export function serve ({ witness, witnessKeys = [] } = {}) {
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, 'http://x').pathname)
    if (witness !== undefined && path.startsWith('/witness/')) return toWitness(witness, req, res, path)
    const m = MOUNTS.find(([p]) => path.startsWith(p))
    const rel = m && normalize(path.slice(m[0].length) || 'index.html')
    if (!m || rel.startsWith('..')) { res.writeHead(404).end(); return }
    try {
      let body = await readFile(join(m[1], rel))
      if (rel === 'index.html') {
        body = body.toString('utf8').replace('<meta name="muid-witness-keys" content="[]">',
          `<meta name="muid-witness-keys" content="${JSON.stringify(witnessKeys).replaceAll('"', '&quot;')}">`)
          .replace('<meta name="muid-rp-id" content="">', '<meta name="muid-rp-id" content="localhost">')
          .replace('<meta name="muid-origin" content="">', `<meta name="muid-origin" content="http://localhost:${server.address().port}">`)
      }
      res.writeHead(200, { 'content-type': TYPES[rel.slice(rel.lastIndexOf('.'))] ?? 'application/octet-stream', 'x-frame-options': 'DENY', 'content-security-policy': "frame-ancestors 'none'" }).end(body)
    } catch { res.writeHead(404).end() }
  })
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ origin: `http://localhost:${server.address().port}`, close: () => server.close() })))
}
