// Translates the model's abstract items (model/settled.mjs) into real signed records, memoized so that each record
// is built and signed once. Roots are letters in the model and P-256 passkeys here; the witness is one Ed25519 key.
import { createHash } from 'node:crypto'
import { p256 } from '@noble/curves/nist.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, root as rootModule } from '../impl.mjs'
import { make, RP_ID, ORIGIN } from '../assertion/helpers.mjs'
import { payloadsOf, genesisOf } from '../../model/recovery.mjs'

const hex = (b) => Buffer.from(b).toString('hex')
export const BASE = 1_800_000_000
const WITNESS_SECRET = Uint8Array.from({ length: 32 }, (_, i) => 120 + i)
export const WITNESS = hex(ed25519.getPublicKey(WITNESS_SECRET))
export const WITNESS_KEYS = Object.freeze([Object.freeze({ key: WITNESS, nbf: 0, exp: BASE + 1_000_000 })])

export const secretOf = (letter) => Uint8Array.from(createHash('sha256').update('muid model root ' + letter).digest())
const keyOf = (letter) => '04' + hex(p256.getPublicKey(secretOf(letter), false).subarray(1))

const memo = new Map()
const once = (k, f) => { if (!memo.has(k)) memo.set(k, f()); return memo.get(k) }

export const rootText = (letter) => once(`root ${letter}`, () => envelope.wrap(envelope.seal('root', { pub: keyOf(letter), rp_id: RP_ID }).payload))
export const rootId = (letter) => once(`rootId ${letter}`, () => rootModule.checkRoot(rootText(letter), { rpId: RP_ID }).id)
export const letterOf = (id) => [...'abcdeot'].find((l) => rootId(l) === id)

export function identityFor (genesis) {
  return rootModule.identityOf(rootId(genesis))
}

// Model membership ids (and the genesis id) to real record ids, built recursively through prev.
function realMembership (genesis, model, payloads) {
  if (model === genesisOf(genesis).id) return { id: identityFor(genesis) }
  return once(`m ${genesis} ${model}`, () => {
    const p = payloads.get(model)
    const prev = realMembership(genesis, p.prev, payloads).id
    const roots = p.roots.map(rootId).sort()
    const body = { identity: identityFor(genesis), prev, epoch: p.n, roots }
    return { ...envelope.seal('membership', body), body }
  })
}

const rootSigned = (type, body, letter) => once(`${type} ${JSON.stringify(body)} ${letter}`, () => {
  const { payload, id } = envelope.seal(type, body)
  return envelope.wrap(payload, { root: rootId(letter), assertion: make({ covers: [id], secret: secretOf(letter) }) })
})

const witnessSigned = (type, body) => once(`${type} ${JSON.stringify(body)}`, () => {
  const { payload } = envelope.seal(type, body)
  const signature = hex(ed25519.sign(envelope.signedBytes(payload), WITNESS_SECRET))
  return envelope.wrap(payload, { signature, witness: WITNESS })
})

// All the model's items for one identity, as grouped record texts, plus the id mapping for comparison.
export function translate (genesis, items) {
  const payloads = payloadsOf(items.filter((it) => it.kind === 'M'))
  const real = (model) => realMembership(genesis, model, payloads).id
  const identity = identityFor(genesis)
  const letters = new Set([genesis])
  const records = { roots: [], memberships: [], contests: [], freezes: [], anchors: [], settlements: [] }
  const idOf = (model) => (model.startsWith('C<') ? null : real(model))
  for (const it of items) {
    if (it.kind === 'M') {
      const p = payloads.get(`M${it.n}{${it.roots.join(',')}}<${it.prev}`)
      const m = realMembership(genesis, p.id, payloads)
      records.memberships.push(rootSigned('membership', m.body, it.signer))
      letters.add(it.signer)
      for (const r of it.roots) letters.add(r)
    } else if (it.kind === 'C') {
      records.contests.push(rootSigned('contest', { identity, record: real(it.record) }, it.signer))
      letters.add(it.signer)
    } else if (it.kind === 'F') {
      records.freezes.push(rootSigned('freeze', { identity, membership: real(it.target) }, it.signer))
      letters.add(it.signer)
    } else if (it.kind === 'A') {
      const record = it.id.startsWith('C<') ? contestRecordId(identity, real(it.id.slice(2))) : idOf(it.id)
      records.anchors.push(witnessSigned('anchor', { identity, record, at: BASE + it.at }))
    } else if (it.kind === 'S') {
      records.settlements.push(witnessSigned('settlement', {
        identity, prev: real(it.prev), outcome: it.outcome === 'contested' ? 'contested' : real(it.outcome), at: BASE + it.at,
      }))
    }
  }
  for (const l of letters) records.roots.push(rootText(l))
  return { records, real }
}

// A contest's record id: the id of its payload (the same for every signer).
function contestRecordId (identity, record) {
  return envelope.seal('contest', { identity, record }).id
}

export const CTX_BASE = Object.freeze({ rpId: RP_ID, origin: ORIGIN, witnessKeys: WITNESS_KEYS })
