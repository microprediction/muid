// W1's hand-written prefix check (SPEC §6, decision 6): any clientDataJSON bytes, signed by the root's passkey over
// valid authenticator data. checkRootAssertion never throws and refuses with one of W6's reasons; an assertion it
// accepts has bytes that JSON.parse reads as W1 requires (the type, challenge, origin and crossOrigin expected, no
// topOrigin, every other member a string), so no second parser could read the four fields differently.
import { REASONS, CTX, make, challengeFor, RECORD, ORIGIN, checkRootAssertion } from '../../tests/assertion/helpers.mjs'

const CHALLENGE = challengeFor([RECORD])

export function fuzz (data) {
  const bytes = Buffer.from(data)
  const r = checkRootAssertion(make({ covers: [RECORD], cdjBytes: bytes }), CTX)
  if (!r.ok) {
    if (!REASONS.includes(r.reason)) throw new Error(`unknown reason ${r.reason}`)
    return
  }
  const text = bytes.toString('utf8')
  let v
  try { v = JSON.parse(text) } catch { throw new Error(`accepted, but JSON.parse refuses it: ${text}`) }
  const want = { type: 'webauthn.get', challenge: CHALLENGE, origin: ORIGIN, crossOrigin: false }
  for (const [k, x] of Object.entries(want)) if (v[k] !== x) throw new Error(`accepted, but JSON.parse reads ${k} as ${JSON.stringify(v[k])}: ${text}`)
  if ('topOrigin' in v) throw new Error(`accepted with topOrigin: ${text}`)
  for (const [k, x] of Object.entries(v)) if (!(k in want) && typeof x !== 'string') throw new Error(`accepted with ${k} not a string: ${text}`)
}
