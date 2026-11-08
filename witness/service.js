// The witness service: the witness's decisions (witness.js) behind a small HTTP API, fetch-style (a Request in, a
// Response out), so it runs on Node or any host with the standard Request and Response. Each identity's holding is
// changed only inside `holdings.update`, which serialises changes to one identity; every record the witness signs is
// appended to `log` before the holding that contains it is kept, so nothing is served that the log did not take.
// The log is the transparency log's (Tessera, research/witness-tlog.md); memoryLog stands in for it in tests.
const ID = /^[0-9a-f]{64}$/
const IDENTITY_PATH = /^\/v1\/identities\/([0-9a-f]{64})\/(records|head)$/
const MAX_BODY = 131072 // bytes: two envelopes of the largest payload, with room
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

  // An entry as the log has it. Records signed but not yet known to be logged wait in the entry's outbox; they are
  // appended (again, if need be: the same texts) before anything else is done for the identity, so a lost answer
  // from the log never leads the witness to sign a rival instead.
  async function settle (entry) {
    if (entry?.outbox === undefined) return entry
    await append(entry.outbox.texts)
    return entry.outbox.entry
  }

  // Runs `step(entry, now)` on the identity's logged entry, inside its update. A step that signs nothing returns
  // { value } or { entry, value }, kept at once; one that signs returns { entry, texts, value }: the entry and texts
  // are kept in the outbox first, then appended, and the value is given only once they are logged.
  async function commit (identity, step) {
    const r = await holdings.update(identity, async (entry) => {
      const e = await settle(entry)
      const s = step(e, clock())
      if (s.texts === undefined) return { entry: s.entry ?? e, value: { done: s.value } }
      return { entry: { ...e, outbox: { entry: s.entry, texts: s.texts } }, value: { staged: s.value } }
    })
    if (r.staged === undefined) return r.done
    await holdings.update(identity, async (entry) => ({ entry: await settle(entry) }))
    return r.staged
  }

  // A submitted record, revocation or delegation: decided against the logged records, advanced, logged, then kept.
  // A delegation's logged record (R10) is signed in the decision itself: appended with the rest when it is new.
  function change (identity, decide) {
    return commit(identity, (entry, now) => {
      const r = decide(entry?.held ?? witness.empty(identity), now)
      if (!r.ok) return { value: refusal(422, r.reason) }
      const a = witness.advance(r.held, now)
      const texts = [...(r.fresh ? [r.logged] : []), ...a.signed.map((x) => x.text)]
      const value = json(200, { ok: true, signed: texts, logged: r.logged })
      // Nothing changed (a record already held, a delegation already logged): the entry, and its head, stay as they are.
      // (A held record or a logged delegation that is new, or anything advance signs, makes a new holding.)
      if (entry !== undefined && a.held === entry.held) return { value }
      // Stryker disable next-line ConditionalExpression: equivalent; an empty outbox appends nothing
      return texts.length === 0 ? { entry: { held: a.held }, value } : { entry: { held: a.held }, texts, value }
    })
  }

  // The current head, reused while it is younger than headInterval and nothing has changed since it was signed.
  function head (identity) {
    return commit(identity, (entry, now) => {
      if (entry === undefined) return { value: refusal(404, 'unknown-identity') }
      if (entry.head !== undefined && now - entry.head.at < headInterval) return { value: json(200, { head: entry.head.text }) }
      const text = witness.head(entry.held, now)
      if (text === undefined) return { value: refusal(409, 'no-head') }
      return { entry: { held: entry.held, head: { text, at: now } }, texts: [text], value: json(200, { head: text }) }
    })
  }

  async function records (identity) {
    // A writer first stores signed records in its outbox, then appends them to the log.  Reading through commit
    // joins that writer's queue and settles its outbox before exposing the holding; a direct get here could otherwise
    // serve a signed record during the small interval before log.append resolves.
    return commit(identity, (entry) => {
      if (entry === undefined) return { value: refusal(404, 'unknown-identity') }
      const out = {}
      for (const k of LISTS) out[k] = entry.held[k]
      out.revocations = entry.held.revocations.map((x) => x.text)
      return { value: json(200, out) }
    })
  }

  async function body (request) {
    // Stryker disable next-line StringLiteral: equivalent; any text that is not JSON is refused as json below
    const text = request.body === null ? '' : await bounded(request, MAX_BODY)
    if (text === undefined) return { error: refusal(413, 'too-large') }
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
    if (pathname !== '/v1/records' && pathname !== '/v1/revocations' && pathname !== '/v1/delegations') return refusal(404, 'not-found')
    if (request.method !== 'POST') return refusal(405, 'method')
    const { b, error } = await body(request)
    if (error !== undefined) return error
    if (pathname === '/v1/records') {
      if (typeof b.type !== 'string') return refusal(400, 'request')
      if (!SUBMITTED.includes(b.type)) return refusal(422, 'type')
      return change(b.identity, (held) => witness.admit(held, b.type, b.text))
    }
    if (pathname === '/v1/delegations') return change(b.identity, (held, now) => witness.log(held, b.text, now))
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
      out.push(...await commit(identity, (entry, now) => {
        const a = witness.advance(entry.held, now)
        const texts = a.signed.map((x) => x.text)
        return texts.length === 0 ? { value: [] } : { entry: { held: a.held }, texts, value: texts }
      }))
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
      // The queue is dropped once its last update is done, so identities only named once leave nothing behind.
      const tail = run.catch(() => {}).then(() => { if (queues.get(identity) === tail) queues.delete(identity) })
      queues.set(identity, tail)
      return run
    },
    // Identities with an update queued or running.
    inFlight () { return queues.size },
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
