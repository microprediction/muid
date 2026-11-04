// The witness service: the witness's decisions (witness.js) behind a small HTTP API, fetch-style (a Request in, a
// Response out), so it runs on Node or any host with the standard Request and Response. Each identity's holding is
// changed only inside `holdings.update`, which serialises changes to one identity; every record the witness signs is
// appended to `log` before the holding that contains it is kept, so nothing is served that the log did not take.
// The log is the transparency log's (Tessera, research/witness-tlog.md); memoryLog stands in for it in tests.
const ID = /^[0-9a-f]{64}$/
const IDENTITY_PATH = /^\/v1\/identities\/([0-9a-f]{64})\/(records|head)$/
const MAX_BODY = 131072 // characters: two envelopes of the largest payload, with room
const SUBMITTED = ['root', 'membership', 'contest', 'freeze']
const LISTS = ['roots', 'memberships', 'contests', 'freezes', 'anchors', 'settlements']

class Unavailable extends Error {
  constructor (reason) {
    super(`${reason} unavailable`)
    this.reason = reason
  }
}

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
const refusal = (status, reason) => json(status, { ok: false, reason })
const isTime = (x) => Number.isSafeInteger(x) && x >= 0

export function witnessService ({ witness, holdings, log, clock, headInterval }) {
  if (typeof witness?.admit !== 'function' || typeof holdings?.update !== 'function' || typeof log?.append !== 'function' ||
    typeof clock !== 'function' || !isTime(headInterval)) {
    throw new TypeError('service configuration must hold witness, holdings, log, clock and a non-negative headInterval')
  }

  // Appends each text to the log, in order; the caller keeps nothing if this throws.
  async function append (texts) {
    try {
      for (const t of texts) await log.append(t)
    } catch {
      throw new Unavailable('log')
    }
  }

  // A submitted record or revocation: decided, advanced and logged inside the identity's update, then kept.
  function change (identity, decide) {
    return holdings.update(identity, async (entry) => {
      const now = clock()
      const r = decide(entry?.held ?? witness.empty(identity), now)
      if (!r.ok) return { value: refusal(422, r.reason) }
      const a = witness.advance(r.held, now)
      const texts = a.signed.map((s) => s.text)
      await append(texts)
      return { entry: { held: a.held }, value: json(200, { ok: true, signed: texts }) }
    })
  }

  // The current head, reused while it is younger than headInterval and nothing has changed since it was signed.
  function head (identity) {
    return holdings.update(identity, async (entry) => {
      if (entry === undefined) return { value: refusal(404, 'unknown-identity') }
      const now = clock()
      if (entry.head !== undefined && now - entry.head.at < headInterval) return { value: json(200, { head: entry.head.text }) }
      const text = witness.head(entry.held, now)
      if (text === undefined) return { value: refusal(409, 'no-head') }
      await append([text])
      return { entry: { held: entry.held, head: { text, at: now } }, value: json(200, { head: text }) }
    })
  }

  async function records (identity) {
    const entry = await holdings.get(identity)
    if (entry === undefined) return refusal(404, 'unknown-identity')
    const out = {}
    for (const k of LISTS) out[k] = entry.held[k]
    out.revocations = entry.held.revocations.map((x) => x.text)
    return json(200, out)
  }

  async function body (request) {
    const text = await request.text()
    if (text.length > MAX_BODY) return { error: refusal(413, 'too-large') }
    let b
    try {
      b = JSON.parse(text)
    } catch {
      return { error: refusal(400, 'json') }
    }
    // JSON has no other value whose fields are strings: a number, string or array gives undefined for each.
    if (b === null || typeof b.identity !== 'string' || !ID.test(b.identity) || typeof b.text !== 'string') {
      return { error: refusal(400, 'request') }
    }
    return { b }
  }

  async function route (request) {
    const { pathname } = new URL(request.url)
    const m = IDENTITY_PATH.exec(pathname)
    if (m !== null) {
      if (request.method !== 'GET') return refusal(405, 'method')
      return m[2] === 'head' ? head(m[1]) : records(m[1])
    }
    if (pathname !== '/v1/records' && pathname !== '/v1/revocations') return refusal(404, 'not-found')
    if (request.method !== 'POST') return refusal(405, 'method')
    const { b, error } = await body(request)
    if (error !== undefined) return error
    if (pathname === '/v1/records') {
      if (typeof b.type !== 'string') return refusal(400, 'request')
      if (!SUBMITTED.includes(b.type)) return refusal(422, 'type')
      return change(b.identity, (held) => witness.admit(held, b.type, b.text))
    }
    if (b.delegation !== undefined && typeof b.delegation !== 'string') return refusal(400, 'request')
    return change(b.identity, (held, now) => witness.revoke(held, b.text, now, b.delegation))
  }

  // A request: its Response. A failure of the log or the store is 503, and nothing is kept.
  async function handle (request) {
    try {
      return await route(request)
    } catch (e) {
      return refusal(503, e instanceof Unavailable ? e.reason : 'storage')
    }
  }

  // Advances every identity at the clock's time: settlements once windows pass, and anchors they make possible.
  // Returns the texts signed, every one logged. A failure of the log or the store rejects.
  async function tick () {
    const out = []
    for (const identity of await holdings.identities()) {
      await holdings.update(identity, async (entry) => {
        const a = witness.advance(entry.held, clock())
        if (a.signed.length === 0) return {}
        const texts = a.signed.map((s) => s.text)
        await append(texts)
        out.push(...texts)
        return { entry: { held: a.held } }
      })
    }
    return out
  }

  return Object.freeze({ handle, tick })
}

// One process's holdings: changes to one identity run one at a time, in arrival order.
export function memoryHoldings () {
  const entries = new Map()
  const queues = new Map()
  return Object.freeze({
    async get (identity) { return entries.get(identity) },
    async identities () { return [...entries.keys()] },
    update (identity, fn) {
      const run = (queues.get(identity) ?? Promise.resolve()).then(async () => {
        const r = await fn(entries.get(identity))
        if (r.entry !== undefined) entries.set(identity, r.entry)
        return r.value
      })
      queues.set(identity, run.catch(() => {}))
      return run
    },
  })
}

// An append-only list standing in for the transparency log.
export function memoryLog () {
  const list = []
  return Object.freeze({
    async append (text) { list.push(text) },
    entries () { return [...list] },
  })
}
