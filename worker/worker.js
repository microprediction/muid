// muid/worker: what a worker does with what the id page hands it (not core; nothing here is trusted by a verifier).
// A worker is an agent's Ed25519 key. Its owner authorises it at the id page, which hands over a delegation signed
// by a passkey; the worker countersigns its acceptance (D6), has the witness log the delegation (R10), and from then
// on signs a claim for each request and presents it with the four records that let a relying party verify it
// offline: the delegation, the root's record, the witness's logged record of the delegation, and a fresh head.
//
//   const key = newKey()                                   // key.subject is what the owner types into the id page
//   const w = await enrol({ handOff, secret: key.secret, witness: 'https://id.example/witness/' })
//   const records = await request(w, key.secret, { scope, method, url, data, at }, { witness })
//
// What `enrol` returns holds no secret and is plain data: it may be stored, and is read back as untrusted (the
// relying party checks every record). The secret is the caller's to keep. How the five records travel with a
// request is the service's choice. Each function throws an Error whose message says what was wrong.
import { ed25519 } from '@noble/curves/ed25519.js'
import { open, seal, wrap, signedBytes } from '../src/envelope.js'
import { rootIdOf } from '../src/root.js'
import { fromHex, toHex } from '../src/bytes.js'

const SECRET = /^[0-9a-f]{64}$/
const ACCEPT = new TextEncoder().encode('muid/v1/accept\n')
const secretBytes = (secret) => {
  if (typeof secret !== 'string' || !SECRET.test(secret)) throw new Error('a worker secret is 64 lowercase hex digits')
  return fromHex(secret)
}

// The public key the owner gives the id page for a secret.
export const subjectOf = (secret) => toHex(ed25519.getPublicKey(secretBytes(secret)))

// A new worker key: { secret, subject }, both hex. `random(bytes)` fills and returns its argument.
export function newKey (random = (bytes) => globalThis.crypto.getRandomValues(bytes)) {
  const secret = toHex(random(new Uint8Array(32)))
  return { secret, subject: subjectOf(secret) }
}

// The id page's hand-off, countersigned: { delegation, id, body }. Refused unless it is a delegation to this key.
export function accept (handOff, secret) {
  const key = secretBytes(secret)
  let h
  try {
    h = JSON.parse(handOff)
  } catch { /* refused below, as anything that is no hand-off */ }
  if (typeof h?.payload !== 'string' || h.root === null || typeof h.root !== 'object') throw new Error('that is not a hand-off from the id page')
  let d
  try {
    d = open(wrap(h.payload, {}), 'delegation') // read for its body and id: its signatures are the verifier's to check
  } catch {
    throw new Error('that is not a hand-off from the id page')
  }
  // The body as plain data (the envelope gives it without prototypes). Its form is the witness's and the verifier's
  // to check: here only what this module reads of it.
  const body = JSON.parse(JSON.stringify(d.body))
  if (!Array.isArray(body.scopes) || typeof body.identity !== 'string') throw new Error('that is not a hand-off from the id page')
  if (body.subject !== toHex(ed25519.getPublicKey(key))) throw new Error('that delegation is for another key')
  const message = new Uint8Array(ACCEPT.length + 32)
  message.set(ACCEPT)
  message.set(fromHex(d.id), ACCEPT.length)
  return { delegation: wrap(h.payload, { root: h.root, subject: toHex(ed25519.sign(message, key)) }), id: d.id, body }
}

// The witness service at `witness` (a URL ending in /), asked with `fetch`: its JSON answer, or an Error.
async function ask (fetch, witness, path, body) {
  if (typeof witness !== 'string' || !witness.endsWith('/')) throw new Error('the witness is a URL ending in /')
  let r
  try {
    r = await fetch(witness + path, body === undefined ? undefined : { method: 'POST', body: JSON.stringify(body) })
    r = { status: r.status, body: await r.json() }
  } catch {
    throw new Error('the witness did not answer')
  }
  if (r.body === null || typeof r.body !== 'object') throw new Error('the witness did not answer')
  return r
}

// Enrolment: the hand-off countersigned, logged by the witness, and joined by the root's record.
//   { identity, id, agent, aud, scopes, nbf, exp, subject, delegation, root, logged }
export async function enrol ({ handOff, secret, witness, fetch = globalThis.fetch }) {
  const { delegation, id, body } = accept(handOff, secret)
  const logging = await ask(fetch, witness, 'v1/delegations', { identity: body.identity, text: delegation })
  if (logging.body.ok !== true || typeof logging.body.logged !== 'string') {
    throw new Error(`the witness refused the delegation: ${typeof logging.body.reason === 'string' ? logging.body.reason : logging.status}`)
  }
  const held = await ask(fetch, witness, `v1/identities/${body.identity}/records`)
  const signer = (text) => {
    try {
      const r = open(text, 'root').body
      return rootIdOf(r.rp_id, r.pub) === body.root
    } catch { /* not a root record: not the signer's */ }
  }
  const root = Array.isArray(held.body.roots) ? held.body.roots.find(signer) : undefined
  if (root === undefined) throw new Error('the witness does not hold the record of the root that signed the delegation')
  return Object.freeze({ identity: body.identity, id, agent: body.agent, aud: body.aud, scopes: Object.freeze([...body.scopes]), nbf: body.nbf, exp: body.exp,
    subject: body.subject, delegation, root, logged: logging.body.logged })
}

// A claim for one request: the method and URL the service will receive, the scope it is made under, its data, and
// the time (seconds). `nonce` and `contentDigest` are given when the service checks them.
export function claim (enrolled, secret, { scope, method, url, data = {}, at, nonce, contentDigest }) {
  const key = secretBytes(secret)
  if (toHex(ed25519.getPublicKey(key)) !== enrolled.subject) throw new Error('that enrolment is another key\'s')
  if (!enrolled.scopes.includes(scope)) throw new Error('the delegation does not give that scope')
  if (!Number.isSafeInteger(at) || at < enrolled.nbf || at >= enrolled.exp) throw new Error('the delegation is not in force at that time: enrol with a renewed one')
  const body = { delegation: enrolled.id, scope, htm: method, htu: url, at, data }
  if (nonce !== undefined) body.nonce = nonce
  if (contentDigest !== undefined) body.content_digest = contentDigest
  const { payload } = seal('claim', body)
  return wrap(payload, { signature: toHex(ed25519.sign(signedBytes(payload), key)) })
}

// The five records a request carries: the claim, with a head the witness signs now.
//   { claim, delegation, root, head, logged }
export async function request (enrolled, secret, options, { witness, fetch = globalThis.fetch }) {
  const text = claim(enrolled, secret, options)
  const r = await ask(fetch, witness, `v1/identities/${enrolled.identity}/head`)
  if (typeof r.body.head !== 'string') throw new Error(`the witness gave no head: ${typeof r.body.reason === 'string' ? r.body.reason : r.status}`)
  return { claim: text, delegation: enrolled.delegation, root: enrolled.root, head: r.body.head, logged: enrolled.logged }
}
