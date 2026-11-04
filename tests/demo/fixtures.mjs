// The demo's unit-test fixtures: the owner's identity (a simulated passkey), workers with delegations to Forecasts,
// heads signed by a witness, and a Forecasts instance over the in-memory log.
import { ed25519 } from '@noble/curves/ed25519.js'
import { envelope, root as rootModule, verifier as verifierModule } from '../impl.mjs'
import { relyingParty, memoryStore } from '../adapter/impl.mjs'
import { witness } from '../witness/impl.mjs'
import { records as idRecords } from '../id/impl.mjs'
import { forecasts } from './impl.mjs'
import { make, RP_ID, ORIGIN, SECRET, KEY } from '../assertion/helpers.mjs'
import { fakeLog, CONFIG } from './fake-log.mjs'

export const hex = (b) => Buffer.from(b).toString('hex')
export const NOW = 1_800_000_000
export const FORECASTS = 'https://forecasts.example'
const W = Uint8Array.from({ length: 32 }, (_, i) => 120 + i)
const WITNESS = hex(ed25519.getPublicKey(W))
export const S = Uint8Array.from({ length: 32 }, (_, i) => 200 + i)
export const SERVICE_KEY = hex(ed25519.getPublicKey(S))
const WITNESS_KEYS = [{ key: WITNESS, nbf: 0, exp: 4_000_000_000 }]
const LIMITS = { skew: 60, maxLifetime: 2_592_000 }

export const rootText = envelope.wrap(envelope.seal('root', { pub: KEY, rp_id: RP_ID }).payload)
const ROOT = rootModule.checkRoot(rootText, { rpId: RP_ID }).id
export const IDENTITY = rootModule.identityOf(ROOT)
const w = witness({ rpId: RP_ID, origin: ORIGIN, witnessKeys: WITNESS_KEYS, key: WITNESS, sign: (b) => hex(ed25519.sign(b, W)), contestWindow: 259_200, ...LIMITS })
const held = w.admit(w.empty(IDENTITY), 'root', rootText).held
export const head = (at = NOW - 10) => w.head(held, at)

export function worker (seed, { aud = FORECASTS, scopes = ['forecast'] } = {}) {
  const secret = Uint8Array.from({ length: 32 }, (_, i) => seed + i)
  const d = idRecords.delegation({ identity: IDENTITY, membership: IDENTITY, root: ROOT, subject: hex(ed25519.getPublicKey(secret)), aud, scopes, now: NOW - 100, lifetime: 3600 })
  const subject = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(d.id, 'hex')]), secret))
  const delegation = envelope.wrap(d.payload, { root: make({ covers: [d.id], secret: SECRET }), subject })
  const claim = (data, at = NOW - 5) => {
    const { payload } = envelope.seal('claim', { delegation: d.id, scope: 'forecast', htm: 'POST', htu: `${aud}/forecasts`, at, data })
    return envelope.wrap(payload, { signature: hex(ed25519.sign(envelope.signedBytes(payload), secret)) })
  }
  return { id: d.id, delegation, claim, records: (data, at) => ({ claim: claim(data, at), delegation, root: rootText, head: head() }) }
}

// `realWait` leaves Forecasts its own pause between polls; otherwise `wait` (by default, none).
export function setup ({ log = fakeLog({ cosignTime: () => NOW }), clock = () => NOW, wait = async () => {}, realWait = false } = {}) {
  const v = verifierModule.verifier({ rpId: RP_ID, origin: ORIGIN, audience: FORECASTS, witnessKeys: WITNESS_KEYS, maxStaleness: 86_400, maxClaimAge: 300, ...LIMITS })
  const f = forecasts({ origin: FORECASTS, adapter: relyingParty({ verifier: v, store: memoryStore() }), log, checkpoints: { ...CONFIG, skew: 60 },
    key: SERVICE_KEY, sign: (b) => hex(ed25519.sign(b, S)), clock, ...(realWait ? {} : { wait }) })
  const post = async (body, init = {}) => {
    const res = await f.handle(new Request(`${FORECASTS}/forecasts`, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body), ...init }))
    return { status: res.status, body: await res.json(), type: res.headers.get('content-type') }
  }
  const get = async (path, init) => {
    const res = await f.handle(new Request(FORECASTS + path, init))
    return { status: res.status, body: await res.json() }
  }
  return { f, log, post, get }
}

export const SERVICES = [{ origin: FORECASTS, key: SERVICE_KEY, nbf: 0, exp: 4_000_000_000 }]
