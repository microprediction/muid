// Forecasts, the demo's service that accepts contributions (research/witness-api-and-demo.md). A worker POSTs a
// claim (C1: a DPoP proof for this request, its forecast in `data`) with its delegation, the delegation's root
// record and a fresh head. The relying-party adapter verifies the claim and consumes it once; only then is the
// forecast kept, and the service signs a receipt (C2), appends it to the transparency log, and keeps it with the
// cosigned checkpoint and inclusion proof from when it was logged, as a Sigstore bundle keeps its own.
import { seal, wrap, signedBytes } from '../src/envelope.js'
import { verifyCheckpoint } from '../src/note.js'

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const ID = /^[0-9a-f]{64}$/
const QUESTION = /^[\x21-\x7e]{1,64}$/

// A contribution's data as a forecast, { question, forecast } (forecast in basis points, 0 to 10,000), or undefined.
function forecastOf (data) {
  if (Object.keys(data).length !== 2) return undefined // and those two are the ones checked below
  const { question, forecast } = data
  if (typeof question !== 'string' || !QUESTION.test(question) || !Number.isSafeInteger(forecast) || forecast < 0 || forecast > 10_000) return undefined
  return { question, forecast }
}
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
  const kept = [] // { identity, agent, delegation, claim, question, forecast, credits, bundle }
  const collected = new Map() // identity -> credits collected

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

  // The four records a request carries, read from its JSON body; or the response refusing it.
  async function read (request) {
    // Stryker disable next-line StringLiteral: equivalent; any text that is not JSON is refused as json below
    const text = request.body === null ? '' : await bounded(request, MAX_BODY)
    if (text === undefined) return { error: json(413, { ok: false, reason: 'too-large' }) }
    let b
    try {
      b = JSON.parse(text)
    } catch {
      return { error: json(400, { ok: false, reason: 'json' }) }
    }
    return { records: { claim: b?.claim, delegation: b?.delegation, root: b?.root, head: b?.head } }
  }

  // A claim for `scope`, verified and consumed by the adapter, then `action(accepted)`; its result as a response.
  async function claimed (request, scope, action) {
    const { records, error } = await read(request)
    if (error !== undefined) return error
    let r
    try {
      r = await adapter.acceptClaim(records, { now: clock(), scope, method: 'POST', url: request.url, revoked: [] }, (accepted) => action(accepted, records))
    } catch {
      // The log, or the adapter's store, failed. The claim may be consumed: the delegate makes a new one.
      return json(503, { ok: false, reason: 'unavailable' })
    }
    if (!r.ok) return json(403, { ok: false, reason: r.reason })
    return r.value.refused === undefined ? json(200, { ok: true, ...r.value }) : json(422, { ok: false, reason: r.value.refused })
  }

  // A contribution: a forecast, kept for the identity of the delegation it was made under (the beneficiary, bound
  // now) and the agent that made it, with its receipt. A claim whose data is not a forecast is spent, and refused.
  const submit = (request) => claimed(request, 'forecast', async (accepted, records) => {
    const f = forecastOf(accepted.body.data)
    if (f === undefined) return { refused: 'forecast' }
    const bundle = await receipt(accepted, clock())
    kept.push({ identity: accepted.delegation.body.identity, agent: accepted.delegation.body.subject, delegation: accepted.delegation.id,
      claim: records.claim, ...f, credits: undefined, bundle })
    return { bundle }
  })

  // Collection: by a live delegation of the identity holding the collect scope (not an agent's, unless granted it).
  const collect = (request) => claimed(request, 'collect', async (accepted) => {
    const identity = accepted.delegation.body.identity
    const amount = earnings(identity).balance
    collected.set(identity, (collected.get(identity) ?? 0) + amount)
    return { collected: amount }
  })

  // An identity's earnings: what its contributions earned once resolved, what was collected, and each agent's share.
  function earnings (identity) {
    const mine = kept.filter((k) => k.identity === identity)
    const agents = []
    for (const k of mine) {
      let a = agents.find((x) => x.delegation === k.delegation)
      if (a === undefined) agents.push(a = { agent: k.agent, delegation: k.delegation, contributions: 0, earned: 0 })
      a.contributions += 1
      a.earned += k.credits ?? 0
    }
    const earned = agents.reduce((n, a) => n + a.earned, 0)
    const took = collected.get(identity) ?? 0
    return { identity, earned, collected: took, balance: earned - took, agents }
  }

  // The operator resolves a question: each forecast of it not yet scored earns its Brier score, in basis points
  // (10,000 - (f - 10,000 o)^2 / 10,000, rounded down). Returns how many were scored.
  function resolve (question, outcome) {
    if (typeof question !== 'string' || (outcome !== 0 && outcome !== 1)) throw new TypeError('a question and an outcome of 0 or 1')
    let n = 0
    for (const k of kept) {
      if (k.question !== question || k.credits !== undefined) continue
      const d = k.forecast - 10_000 * outcome
      k.credits = 10_000 - Math.floor(d * d / 10_000)
      n++
    }
    return n
  }

  // An identity's contributions, each with its receipt bundle and the claim it names.
  function contributions (identity) {
    return json(200, kept.filter((k) => k.identity === identity).map((k) => ({ ...k.bundle, claim: k.claim })))
  }

  async function handle (request) {
    const url = new URL(request.url)
    const only = (method, f) => (request.method === method ? f() : json(405, { ok: false, reason: 'method' }))
    if (url.pathname === '/forecasts') return only('POST', () => submit(request))
    if (url.pathname === '/collect') return only('POST', () => collect(request))
    if (url.pathname === '/contributions') return only('GET', () => contributions(url.searchParams.get('identity')))
    if (url.pathname === '/earnings') {
      return only('GET', () => {
        const identity = url.searchParams.get('identity')
        // A missing identity is null, which is not an id.
        return ID.test(identity) ? json(200, earnings(identity)) : json(400, { ok: false, reason: 'identity' })
      })
    }
    return json(404, { ok: false, reason: 'not-found' })
  }

  return Object.freeze({ handle, resolve })
}
