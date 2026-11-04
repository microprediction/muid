// Forecasts, the demo's service that accepts contributions (research/witness-api-and-demo.md). A worker POSTs a
// claim (C1: a DPoP proof for this request, its forecast in `data`) with its delegation, the delegation's root
// record and a fresh head. The relying-party adapter verifies the claim and consumes it once; only then is the
// forecast kept, and the service signs a receipt (C2), appends it to the transparency log, and keeps it with the
// cosigned checkpoint and inclusion proof from when it was logged, as a Sigstore bundle keeps its own.
import { seal, wrap, signedBytes } from '../src/envelope.js'
import { verifyCheckpoint } from '../src/note.js'

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const MAX_BODY = 262144 // bytes: four records of the largest payload, with room

// The request body as UTF-8 text, read only up to `max` bytes: undefined past them, the rest never read.
async function bounded (request, max) {
  const chunks = []
  let n = 0
  const reader = request.body.getReader()
  for (let r = await reader.read(); !r.done; r = await reader.read()) {
    n += r.value.length
    if (n > max) {
      await reader.cancel()
      return undefined
    }
    chunks.push(r.value)
  }
  const all = new Uint8Array(n)
  let at = 0
  for (const c of chunks) { all.set(c, at); at += c.length }
  return new TextDecoder().decode(all)
}

export function forecasts ({ origin, adapter, log, checkpoints, key, sign, clock, wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }) {
  // Stryker disable next-line ArrayDeclaration: equivalent; a stray element has no identity, so is never listed
  const kept = [] // { identity, claim, data, bundle }

  // A checkpoint whose tree holds entry `index`, verified under the log's configuration: polled until one is
  // published (the log publishes once its witnesses have cosigned).
  async function covering (index) {
    for (let i = 0; i < 300; i++) {
      const text = await log.checkpoint()
      const c = verifyCheckpoint(text, { ...checkpoints, now: clock() })
      if (c.ok && c.size > index) return { text, size: c.size }
      await wait(100)
    }
    // Stryker disable next-line all: equivalent; without it the caller fails on the missing checkpoint instead, and
    // answers 503 all the same
    throw new Error('no cosigned checkpoint holds the receipt')
  }

  async function receipt (accepted, now) {
    const body = { service: origin, identity: accepted.delegation.body.identity, delegation: accepted.delegation.id, claim: accepted.id, at: now }
    const { payload } = seal('receipt', body)
    const text = wrap(payload, { signature: sign(signedBytes(payload)), service: key })
    const index = await log.append(text)
    const c = await covering(index)
    const proof = (await log.inclusionProof(index, c.size)).map(hex)
    return { receipt: text, checkpoint: c.text, proof, index }
  }

  async function submit (request) {
    // Stryker disable next-line StringLiteral: equivalent; any text that is not JSON is refused as json below
    const text = request.body === null ? '' : await bounded(request, MAX_BODY)
    if (text === undefined) return json(413, { ok: false, reason: 'too-large' })
    let b
    try {
      b = JSON.parse(text)
    } catch {
      return json(400, { ok: false, reason: 'json' })
    }
    const records = { claim: b?.claim, delegation: b?.delegation, root: b?.root, head: b?.head }
    const now = clock()
    let r
    try {
      r = await adapter.acceptClaim(records, { now, scope: 'forecast', method: 'POST', url: request.url, revoked: [] }, async (accepted) => {
        const bundle = await receipt(accepted, now)
        kept.push({ identity: accepted.delegation.body.identity, claim: records.claim, data: accepted.body.data, bundle })
        return bundle
      })
    } catch {
      // The log, or the adapter's store, failed. The claim may be consumed: the delegate makes a new one.
      return json(503, { ok: false, reason: 'unavailable' })
    }
    return r.ok ? json(200, { ok: true, bundle: r.value }) : json(403, { ok: false, reason: r.reason })
  }

  // An identity's contributions, each with its receipt bundle and the claim it names.
  function contributions (identity) {
    return json(200, kept.filter((k) => k.identity === identity).map((k) => ({ ...k.bundle, claim: k.claim })))
  }

  async function handle (request) {
    const url = new URL(request.url)
    if (url.pathname === '/forecasts') return request.method === 'POST' ? submit(request) : json(405, { ok: false, reason: 'method' })
    if (url.pathname === '/contributions') {
      return request.method === 'GET' ? contributions(url.searchParams.get('identity')) : json(405, { ok: false, reason: 'method' })
    }
    return json(404, { ok: false, reason: 'not-found' })
  }

  return Object.freeze({ handle })
}
