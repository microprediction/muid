// Forecasts, the demo's service that accepts contributions (research/witness-api-and-demo.md). A worker POSTs a
// claim (C1: a DPoP proof for this request, its forecast in `data`) with its delegation, the delegation's root
// record, the witness's logged record of it (R10) and a fresh head. The relying-party adapter verifies the claim and
// consumes it once; only then is the forecast kept, with a receipt (C2) the service signs at once. The receipt is then
// appended to the transparency log and kept with the cosigned checkpoint and inclusion proof from when it was logged,
// as a Sigstore bundle keeps its own; a contribution whose receipt is not yet published stays kept, and `publish`
// retries it (an outbox).
//
// Reward policy, as forecasting tournaments score: the operator asks each question with a closing time; each identity
// holds one standing forecast per question, its latest before the question closes, whichever of its agents made it;
// a question resolves once, and only standing forecasts earn. More agents, or more claims, earn nothing more.
import { seal, wrap, signedBytes } from '../src/envelope.js'
import { verifyCheckpoint } from '../src/note.js'
import { verifyInclusion, leafHash } from '../src/merkle.js'

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const bytes = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16))
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
  const kept = [] // { identity, agent, delegation, claim, question, forecast, receipt, index, bundle, credits }
  const collected = new Map() // identity -> credits collected
  const questions = new Map() // question -> { closes, outcome }

  // A checkpoint whose tree holds entry `index`, verified under the log's configuration: polled until one is
  // published (the log publishes once its witnesses have cosigned).
  async function covering (index) {
    for (let i = 0; i < 300; i++) {
      const text = await log.checkpoint()
      const c = verifyCheckpoint(text, { ...checkpoints, now: clock() })
      if (c.ok && c.size > index) return { text, size: c.size, root: c.root }
      await wait(100)
    }
    // Stryker disable next-line all: equivalent; without it the caller fails on the missing checkpoint instead, and
    // answers 503 all the same
    throw new Error('no cosigned checkpoint holds the receipt')
  }

  function receipt (accepted, now) {
    const body = { service: origin, identity: accepted.delegation.body.identity, delegation: accepted.delegation.id, claim: accepted.id, at: now }
    const { payload } = seal('receipt', body)
    return wrap(payload, { signature: sign(signedBytes(payload)), service: key })
  }

  // Publishes a kept contribution's receipt: appended once (its index kept as soon as the log gives it), then bundled
  // with a covering checkpoint and a proof that it holds the receipt, checked before it is kept. True once bundled by
  // this call; false if the log failed or gave a wrong proof (to be retried), or another call is publishing it.
  async function published (k) {
    if (k.flight !== undefined) { await k.flight; return false } // one publication of a contribution at a time
    k.flight = attempt(k)
    try { return await k.flight } finally { k.flight = undefined }
  }
  async function attempt (k) {
    try {
      if (k.index === undefined) k.index = await log.append(k.receipt)
      const c = await covering(k.index)
      const proof = await log.inclusionProof(k.index, c.size)
      const leaf = leafHash(new TextEncoder().encode(k.receipt))
      if (!verifyInclusion({ leafHash: leaf, index: k.index, size: c.size, proof, root: bytes(c.root) })) return false
      k.bundle = { receipt: k.receipt, checkpoint: c.text, proof: proof.map(hex), index: k.index }
    } catch { /* the log failed: `publish` retries from what is kept */ }
    return k.bundle !== undefined
  }

  // The outbox: retries every contribution whose receipt is not yet bundled. Returns how many it bundled.
  async function publish () {
    let n = 0
    for (const k of kept) if (k.bundle === undefined && await published(k)) n++
    return n
  }

  // The five records a request carries, read from its JSON body; or the response refusing it.
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
    return { records: { claim: b?.claim, delegation: b?.delegation, root: b?.root, head: b?.head, logged: b?.logged } }
  }

  // A claim for `scope`, verified and consumed by the adapter, then `action(accepted)`; its result as a response.
  async function claimed (request, scope, action) {
    const { records, error } = await read(request)
    if (error !== undefined) return error
    let r
    try {
      r = await adapter.acceptClaim(records, { now: clock(), scope, method: 'POST', url: request.url, revoked: [] }, (accepted) => action(accepted, records))
    } catch {
      // The action failed before anything was kept (the service could not sign its receipt). The claim may be
      // consumed: the delegate makes a new one.
      return json(503, { ok: false, reason: 'unavailable' })
    }
    if (!r.ok) return json(403, { ok: false, reason: r.reason })
    if (r.value.refused !== undefined) return json(422, { ok: false, reason: r.value.refused })
    return json(r.value.pending ? 202 : 200, { ok: true, ...r.value })
  }

  // A contribution: a forecast for an open question, kept for the identity of the delegation it was made under (the
  // beneficiary, bound now) and the agent that made it, with its signed receipt, before the receipt is published. A
  // claim whose data is not a forecast, or is for a question not open, is spent, and refused.
  const submit = (request) => claimed(request, 'forecast', async (accepted, records) => {
    const f = forecastOf(accepted.body.data)
    if (f === undefined) return { refused: 'forecast' }
    const now = clock()
    const q = questions.get(f.question)
    if (q === undefined || q.outcome !== undefined || now >= q.closes) return { refused: 'question' }
    const k = { identity: accepted.delegation.body.identity, agent: accepted.delegation.body.subject, delegation: accepted.delegation.id,
      claim: records.claim, signedAt: accepted.body.at, ...f, receipt: receipt(accepted, now), index: undefined, bundle: undefined, credits: undefined }
    kept.push(k)
    return (await published(k)) ? { bundle: k.bundle } : { pending: true, receipt: k.receipt }
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

  // The operator asks a question, open to forecasts until `closes` (the service's time).
  function ask (question, closes) {
    if (typeof question !== 'string' || !QUESTION.test(question) || !Number.isSafeInteger(closes) || closes < 0) throw new TypeError('a question and a closing time')
    if (questions.has(question)) throw new Error('already asked')
    questions.set(question, { closes, outcome: undefined })
  }

  // The operator resolves a question, once: each identity's standing forecast, its last kept, earns its Brier score in
  // basis points (10,000 - (f - 10,000 o)^2 / 10,000, rounded down). Returns how many were scored: none when the same
  // outcome is given again; another outcome is an error.
  function resolve (question, outcome) {
    if (typeof question !== 'string' || (outcome !== 0 && outcome !== 1)) throw new TypeError('a question and an outcome of 0 or 1')
    const q = questions.get(question)
    if (q === undefined) throw new Error('not asked')
    if (q.outcome !== undefined) {
      if (q.outcome !== outcome) throw new Error('already resolved with the other outcome')
      return 0
    }
    q.outcome = outcome
    // Each identity's standing forecast: the one its agent signed last (the claim's own time), not the last to arrive,
    // so one held back on the network cannot stand over a later one; of two signed in one second, the later to arrive.
    const standing = new Map()
    for (const k of kept) {
      if (k.question !== question) continue
      const s = standing.get(k.identity)
      if (s === undefined || k.signedAt >= s.signedAt) standing.set(k.identity, k)
    }
    for (const k of standing.values()) {
      const d = k.forecast - 10_000 * outcome
      k.credits = 10_000 - Math.floor(d * d / 10_000)
    }
    return standing.size
  }

  // An identity's contributions, each with its receipt bundle and the claim it names; one not yet published, with its
  // receipt alone, marked pending.
  function contributions (identity) {
    return json(200, kept.filter((k) => k.identity === identity)
      .map((k) => (k.bundle === undefined ? { receipt: k.receipt, claim: k.claim, pending: true } : { ...k.bundle, claim: k.claim })))
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

  return Object.freeze({ handle, ask, resolve, publish })
}
