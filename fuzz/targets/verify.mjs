// verifyDelegation and verifyClaim (SPEC §6 F5, C1) on a valid set of records with one of them spliced: the input
// names the record, a position, how many characters to delete and what to insert. Neither function throws for any
// record text; each refuses with a reason; and nothing changed is accepted, since every byte of a record is signed.
import { ed25519 } from '@noble/curves/ed25519.js'
import { verifier as verifierModule, envelope, root as rootModule } from '../../tests/impl.mjs'
import { make, KEY, RP_ID, ORIGIN } from '../../tests/assertion/helpers.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
const NOW = 1_800_000_100
const W = Uint8Array.from({ length: 32 }, (_, i) => 140 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
const APP = Uint8Array.from({ length: 32 }, (_, i) => 60 + i)
const AUD = 'https://app.example'
const URL_ = 'https://app.example/posts'
const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: AUD, witnessKeys: [{ key: WITNESS, nbf: 0, exp: 1_900_000_000 }],
  skew: 60, maxLifetime: 2_592_000, maxStaleness: 86_400, maxClaimAge: 300 })

const witnessSigned = (type, body) => {
  const { payload } = envelope.seal(type, body)
  return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), W)), witness: WITNESS })
}
const root = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(root, { rpId: RP_ID }).id
const IDENTITY = rootModule.identityOf(ROOT)
const del = envelope.seal('delegation', { identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(APP)),
  aud: AUD, scopes: ['post'], nbf: NOW - 10, exp: NOW + 86_000 })
const delegation = envelope.wrap(del.payload, { root: make({ covers: [del.id] }),
  subject: hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(del.id, 'hex')]), APP)) })
const head = witnessSigned('head', { identity: IDENTITY, epoch: 1, memberships: [IDENTITY], authority: [ROOT], revoked: [], at: NOW - 100 })
const logged = witnessSigned('logged', { identity: IDENTITY, delegation: del.id, at: NOW - 10 })
const cl = envelope.seal('claim', { delegation: del.id, scope: 'post', htm: 'POST', htu: URL_, at: NOW - 5, data: { text: 'hello' } })
const claim = envelope.wrap(cl.payload, { signature: hex(ed25519.sign(envelope.signedBytes(cl.payload), APP)) })

export const RECORDS = Object.freeze({ claim, delegation, root, head, logged })
const NAMES = Object.keys(RECORDS)
const CALL = Object.freeze({ now: NOW, scope: 'post', method: 'POST', url: URL_, revoked: [] })

// The splice the input describes: byte 0 the record (and, in its top bit, whether the insert is read as UTF-8 or as
// Latin-1), bytes 1–2 the position, byte 3 the number of characters deleted (0–15), the rest the insert.
export function splice (data) {
  const b = Buffer.from(data)
  const name = NAMES[(b[0] ?? 0) % NAMES.length]
  const text = RECORDS[name]
  const at = (((b[1] ?? 0) << 8) | (b[2] ?? 0)) % (text.length + 1)
  const insert = b.subarray(4).toString((b[0] ?? 0) & 0x80 ? 'latin1' : 'utf8')
  return { name, text: text.slice(0, at) + insert + text.slice(at + ((b[3] ?? 0) % 16)) }
}

export function fuzz (data) {
  const { name, text } = splice(data)
  const records = { ...RECORDS, [name]: text }
  const changed = text !== RECORDS[name]
  for (const [what, r] of [['verifyDelegation', v.verifyDelegation(records, CALL)], ['verifyClaim', v.verifyClaim(records, CALL)]]) {
    if (r.ok === true) {
      if (changed && (what === 'verifyClaim' || name !== 'claim')) throw new Error(`${what} accepted a changed ${name}: ${JSON.stringify(text)}`)
    } else if (r.ok !== false || typeof r.reason !== 'string') throw new Error(`${what} returned ${JSON.stringify(r)}`)
  }
}
