// muid/testing: test support for services built on muid. Not for production, and not part of the stable surface.
//
// A service behind the adapter is tested best against the real verifier, with requests made as real ones are. This
// gives what that needs and nothing else: an identity whose "passkey" is a key in memory, an in-process witness (and
// the same witness as a service to fetch from), the five records a request carries, the hand-off the id page would
// give a worker's key, and an in-memory transparency log whose checkpoints are cosigned by a test key.
// Everything is built through muid's other public entries, so it can do nothing a consumer could not.
//
// The passkey here is software: it asserts a user verification that never happened. That is the point in a test and
// the reason never to use it for anything else.
import { p256 } from '@noble/curves/nist.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { seal, wrap, signedBytes, open } from 'muid/envelope'
import { checkRoot, identityOf, agentIdOf } from 'muid/root'
import { membershipState, recoveryCommitment } from 'muid/membership'
import { witness } from 'muid/witness'
import { witnessService, memoryLog, serial } from 'muid/witness/service'
import { leafHash } from 'muid/merkle'

const utf8 = (s) => new TextEncoder().encode(s)
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const unhex = (s) => Uint8Array.from(s.match(/../g), (x) => parseInt(x, 16))
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) { out.set(p, at); at += p.length }
  return out
}
const b64 = (b) => btoa(String.fromCharCode(...b))
const b64u = (b) => b64(b).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
const wallClock = () => Math.floor(Date.now() / 1000)
const secretFor = (...names) => sha256(utf8(names.join('\n')))

// An identity with one root, registered with a witness of its own. `seed` names it: the same seed gives the same
// keys. `clock` gives the time, in seconds, wherever a time is not passed.
//   { identity, root, rootText, verifier, head(at), agent(options), handOff(options), witness: { url, witness, fetch },
//     passkey(name), change(options), recover(options), advance(at), records() }
// Its membership changes as the id page would change it (R1–R11): `change` and `recover` hand records to the witness,
// which anchors, gives notice, says a recovery matured and settles only when `advance` brings its clock there.
// `verifier` is the part of a verifier's configuration that this identity and its witness fix: spread it into
// `verifier({ ...id.verifier, audience, maxStaleness, maxClaimAge })`.
export function testIdentity ({ seed = 'muid testing', rpId = 'id.test', origin = 'https://id.test', clock = wallClock, skew = 60, maxLifetime = 2_592_000 } = {}) {
  const witnessSecret = secretFor('witness', seed)
  const witnessKeys = [{ key: hex(ed25519.getPublicKey(witnessSecret)), nbf: 0, exp: 4_000_000_000 }]
  const w = witness({ rpId, origin, witnessKeys, key: witnessKeys[0].key, sign: (b) => hex(ed25519.sign(b, witnessSecret)), contestWindow: 259_200, skew, maxLifetime })
  // Software passkeys by name (the first is this identity's first root; others may join it, or be recovery parties):
  // the same seed and name give the same key, root record and recovery salt.
  const keys = new Map()
  function passkey (name) {
    const secret = secretFor('passkey', seed, ...(name === undefined ? [] : [name]))
    const text = wrap(seal('root', { pub: hex(p256.getPublicKey(secret, false)), rp_id: rpId }).payload)
    const id = checkRoot(text, { rpId }).id
    keys.set(id, secret)
    return { root: id, rootText: text, salt: hex(secretFor('salt', seed, String(name))) }
  }
  const { rootText, root } = passkey()
  const identity = identityOf(root)
  const taken = (r, what) => {
    if (!r.ok) throw new Error(`muid/testing: the test witness refused ${what}: ${r.reason}`)
    return r
  }
  // What the witness holds for this identity: one holding, whether it is changed here or through the service below.
  let entry = { held: taken(w.admit(w.empty(identity), 'root', rootText), 'the root').held }

  // The root's assertion over `covers` (SPEC §6), as an authenticator that verified the user would give it.
  function assertion (covers, by = root) {
    const passkey = keys.get(by)
    const challenge = b64u(sha256(utf8('muid/v1/assert\n' + covers.map((id) => id + '\n').join(''))))
    const clientData = utf8(`{"type":"webauthn.get","challenge":"${challenge}","origin":"${origin}","crossOrigin":false}`)
    const authData = concat(sha256(utf8(rpId)), Uint8Array.of(0x1d, 0, 0, 0, 0))
    const signature = p256.sign(concat(authData, sha256(clientData)), passkey, { format: 'der', prehash: true })
    return { covers, authenticator_data: b64u(authData), client_data_json: b64u(clientData), signature: b64u(signature) }
  }

  const head = (at = clock()) => w.head(entry.held, at)
  const ctx = { identity, rpId, origin, witnessKeys }
  const state = () => membershipState(entry.held, ctx)
  const admit = (type, text, what, partyRoot) => { entry = { held: taken(w.admit(entry.held, type, text, partyRoot), what).held } }

  // The witness's clock comes to `at`: what is due is anchored, put under notice, said to have matured, or settled.
  const advance = (at = clock()) => { entry = { held: w.advance(entry.held, at).held } }

  // An ordinary change of the settled membership, signed by each of its roots and each root it adds: `add` passkeys by
  // name, `remove` root ids, and `parties` (names) designated with `threshold` and `window`; `parties` left out keeps
  // the designation in force, and null ends it. It is pending until `advance` passes the contest window.
  function change ({ add = [], remove = [], parties, threshold = 1, window = 259_200, at = clock() } = {}) {
    const s = state()
    const added = add.map(passkey)
    const roots = [...s.roots.filter((r) => !remove.includes(r)), ...added.map((k) => k.root)].sort()
    const recovery = parties === undefined ? s.recovery : parties === null ? null : { parties: parties.map((n) => { const k = passkey(n); return recoveryCommitment(k.root, k.salt) }).sort(), threshold, window }
    const m = seal('membership', { identity, prev: s.membership, epoch: s.epoch + 1, roots, ...(recovery === null ? {} : { recovery: { parties: [...recovery.parties], threshold: recovery.threshold, window: recovery.window } }) })
    // The witness takes a root record once a membership it holds names it: the change first, then its new roots.
    for (const r of s.roots) admit('membership', wrap(m.payload, { root: r, assertion: assertion([m.id], r) }), 'a change')
    for (const k of added) {
      admit('root', k.rootText, 'a root')
      admit('membership', wrap(m.payload, { root: k.root, assertion: assertion([m.id], k.root) }), 'a change')
    }
    advance(at)
    return { id: m.id }
  }

  // A recovery by the designated `parties` (names) to `keep` (root ids it keeps) and `add` (passkeys by name), signed
  // by those parties and every root it adds: the witness puts it under notice, and it matures after the designation's
  // window and settles after the contest window, as `advance` brings the clock there. `added`: the roots it adds.
  function recover ({ keep = [], add = [], parties, at = clock() }) {
    const s = state()
    const added = add.map(passkey)
    const m = seal('membership', { identity, prev: s.membership, epoch: s.epoch + 1, roots: [...keep, ...added.map((k) => k.root)].sort() })
    for (const n of parties) {
      const k = passkey(n)
      admit('membership', wrap(m.payload, { assertion: assertion([m.id], k.root), root: k.root, salt: k.salt }), 'a party\'s signature', k.rootText)
    }
    for (const k of added) {
      admit('root', k.rootText, 'a root')
      admit('membership', wrap(m.payload, { root: k.root, assertion: assertion([m.id], k.root) }), 'a recovery')
    }
    advance(at)
    return { id: m.id, added: added.map((k) => k.root).sort() }
  }

  // The identity's records as the witness serves them (GET /v1/identities/<identity>/records).
  const records = async () => (await fetchWitness(`${url}v1/identities/${identity}/records`)).json()

  // The same witness as the service a worker fetches from, at `witness.url`. The object is what muid/worker takes:
  // `enrol({ handOff, secret, ...who.witness })`, `request(enrolled, secret, options, who.witness)`.
  // It holds this identity's records, the same ones `agent` and `revoke` change, and takes others' as any witness.
  const others = new Map()
  const queue = serial()
  const holdings = {
    async get (id) { return id === identity ? entry : others.get(id) },
    async identities () { return [identity, ...others.keys()] },
    update (id, step) {
      return queue.run(id, async () => {
        const r = await step(id === identity ? entry : others.get(id))
        if (r.entry !== undefined) { if (id === identity) entry = r.entry; else others.set(id, r.entry) }
        return r.value
      })
    }
  }
  const service = witnessService({ witness: w, holdings, log: memoryLog(), clock, headInterval: 0 })
  const url = origin + '/witness/'
  const fetchWitness = async (input, init) => {
    const at = String(input)
    if (!at.startsWith(url)) throw new TypeError(`muid/testing: the test witness is at ${url}, not ${at}`)
    return service.handle(new Request('http://witness.test/' + at.slice(url.length), init))
  }

  // What the id page hands a worker whose key is `subject`: the delegation's payload and the root's assertion over
  // it, as one line of JSON. The worker countersigns it (muid/worker's `enrol`).
  function handOff ({ subject, aud, scopes, agent = 'worker', lifetime = 3600, at = clock() }) {
    const d = seal('delegation', { agent, identity, membership: state().membership, root, subject, aud, scopes: [...new Set(scopes)].sort(), nbf: at, exp: at + lifetime })
    return JSON.stringify({ payload: d.payload, root: assertion([d.id]) })
  }

  // A worker authorised for `aud` with `scopes`, by the first root or the passkey named `passkey` (one with authority
  // in the current membership): its delegation, logged by the witness, and its signed claims.
  //   { id, name, subject, agentId, delegation, logged, claim(options), records(options), revoke(at) }
  function agent ({ name = 'worker', aud, scopes, lifetime = 3600, at = clock(), passkey: by }) {
    const signer = by === undefined ? root : passkey(by).root
    const secret = secretFor('agent', seed, name, aud, ...(by === undefined ? [] : [by]))
    const subject = hex(ed25519.getPublicKey(secret))
    const d = seal('delegation', { agent: name, identity, membership: state().membership, root: signer, subject, aud, scopes: [...new Set(scopes)].sort(), nbf: at, exp: at + lifetime })
    const consent = hex(ed25519.sign(concat(utf8('muid/v1/accept\n'), unhex(d.id)), secret))
    const delegation = wrap(d.payload, { root: assertion([d.id], signer), subject: consent })
    const logging = taken(w.log(entry.held, delegation, at), 'the delegation')
    entry = { held: logging.held }
    // A claim for one request: the method and URL the service receives, and its data. `nonce` and `contentDigest`
    // are given when the service checks them.
    const claim = ({ scope = scopes[0], method = 'POST', url, data = {}, at = clock(), nonce, contentDigest }) => {
      const body = { delegation: d.id, scope, htm: method, htu: url, at, data }
      if (nonce !== undefined) body.nonce = nonce
      if (contentDigest !== undefined) body.content_digest = contentDigest
      const { payload } = seal('claim', body)
      return wrap(payload, { signature: hex(ed25519.sign(signedBytes(payload), secret)) })
    }
    // The five records a request carries. `headAt` dates the head; by default it is signed now.
    const signerText = signer === root ? rootText : passkey(by).rootText
    const records = (options) => ({ claim: claim(options), delegation, root: signerText, head: head(options.headAt), logged: logging.logged })
    // The owner revokes this delegation: heads signed from `at` on list it.
    const revoke = (at = clock()) => {
      const r = seal('revocation', { identity, target: d.id, at })
      entry = { held: taken(w.revoke(entry.held, wrap(r.payload, { root: signer, assertion: assertion([r.id], signer) }), at, delegation), 'the revocation').held }
    }
    return { id: d.id, name, subject, agentId: agentIdOf(identity, name), delegation, logged: logging.logged, claim, records, revoke }
  }

  return { identity, root, rootText, verifier: { rpId, origin, witnessKeys, skew, maxLifetime }, head, agent, handOff, witness: { url, witness: url, fetch: fetchWitness },
    passkey: (name) => { const k = passkey(name); return { root: k.root, rootText: k.rootText } }, change, recover, advance, records }
}

// An in-memory transparency log with the interface of `tesseraLog` (append, checkpoint, inclusionProof): RFC 9162
// trees, and C2SP checkpoints signed by a log key and cosigned by one witness key at the clock's time.
//   { append(text), checkpoint(), inclusionProof(index, size), entries(), checkpoints }
// `checkpoints` is the matching configuration for `verifyCheckpoint`, and the `log` of `verifyReceipt`'s context.
export function testLog ({ seed = 'muid testing', origin = 'log.test/muid', clock = wallClock } = {}) {
  // A signed note's key: its id is the first four bytes of SHA-256(name, 0x0A, type, public key).
  const key = (name, type) => {
    const secret = secretFor('log', seed, name)
    const pub = ed25519.getPublicKey(secret)
    const id = sha256(concat(utf8(name), Uint8Array.of(0x0a, type), pub)).subarray(0, 4)
    return { name, secret, id, vkey: `${name}+${hex(id)}+${b64(concat(Uint8Array.of(type), pub))}` }
  }
  const log = key(origin, 1)
  const cosigner = key('witness.test/muid', 4)
  const entries = []
  const node = (l, r) => sha256(concat(Uint8Array.of(1), l, r))
  const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k }
  const rootOf = (h) => h.length === 0 ? sha256(new Uint8Array(0)) : h.length === 1 ? h[0] : node(rootOf(h.slice(0, split(h.length))), rootOf(h.slice(split(h.length))))
  const path = (m, h) => {
    if (h.length === 1) return []
    const k = split(h.length)
    return m < k ? [...path(m, h.slice(0, k)), rootOf(h.slice(k))] : [...path(m - k, h.slice(k)), rootOf(h.slice(0, k))]
  }
  const leaves = (size) => entries.slice(0, size).map((t) => leafHash(utf8(t)))
  return {
    entries: () => [...entries],
    async append (text) {
      entries.push(text)
      return entries.length - 1
    },
    async checkpoint () {
      const text = `${origin}\n${entries.length}\n${b64(rootOf(leaves(entries.length)))}\n`
      const time = clock()
      const stamp = new Uint8Array(8)
      new DataView(stamp.buffer).setBigUint64(0, BigInt(time))
      const signed = `— ${log.name} ${b64(concat(log.id, ed25519.sign(utf8(text), log.secret)))}\n`
      const cosigned = `— ${cosigner.name} ${b64(concat(cosigner.id, stamp, ed25519.sign(utf8(`cosignature/v1\ntime ${time}\n${text}`), cosigner.secret)))}\n`
      return text + '\n' + signed + cosigned
    },
    async inclusionProof (index, size) {
      if (!(Number.isInteger(index) && Number.isInteger(size) && index >= 0 && index < size && size <= entries.length)) throw new RangeError('muid/testing: no such entry at that size')
      return path(index, leaves(size))
    },
    checkpoints: Object.freeze({ origin, log: log.vkey, cosigners: Object.freeze([cosigner.vkey]), quorum: 1 }),
  }
}
