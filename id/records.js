// The id page's records (SPEC §8), built with the core's own functions: the root record from a new passkey, the W1
// challenge, the assertion object (W0–W6) from what the passkey returns, and a delegation to a worker's key, whose
// fields the page shows (I4) before the passkey signs. Nothing here signs; the passkey does, in the browser.
import { sha256 } from '@noble/hashes/sha2.js'
import { seal, wrap } from '../src/envelope.js'
import { checkRoot, identityOf } from '../src/root.js'
import { isCanonicalOrigin } from '../src/origin.js'
import { checkEd25519Key } from '../src/ed25519.js'

// A P-256 SubjectPublicKeyInfo (RFC 5480) is this 26-byte header and the 65-byte uncompressed point.
const SPKI_P256 = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
const ASSERT_PREFIX = 'muid/v1/assert\n'
const SCOPE = /^[a-z][a-z0-9_.:-]{0,63}$/
export const MAX_LIFETIME = 2_592_000 // 30 days (decision 3)

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
// Unpadded base64url (RFC 4648 §5), as WebAuthn fields are written (W6).
export function b64u (buf) {
  let s = ''
  for (const x of new Uint8Array(buf)) s += String.fromCharCode(x)
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}
export const fromB64u = (s) => Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0))

// The root record for a new passkey: { text, id, identity }. Only ES256 (alg -7) on P-256 (I6).
export function rootRecord (spki, alg, rpId) {
  if (alg !== -7) throw new Error('the passkey must use ES256 (P-256)')
  const b = new Uint8Array(spki)
  if (b.length !== 91 || hex(b.subarray(0, 26)) !== SPKI_P256) throw new Error('the passkey did not give a P-256 public key')
  const text = wrap(seal('root', { pub: hex(b.subarray(26)), rp_id: rpId }).payload)
  const r = checkRoot(text, { rpId })
  if (!r.ok) throw new Error(`the passkey's key is not usable: ${r.reason}`)
  return { text, id: r.id, identity: identityOf(r.id) }
}

// W1: SHA-256 of the prefix and each covered id followed by a newline, as the bytes the passkey is asked to sign.
export function challenge (covers) {
  return sha256(new TextEncoder().encode(ASSERT_PREFIX + covers.map((id) => id + '\n').join('')))
}

// The assertion object (W6) from a WebAuthn assertion response's three buffers.
export function assertion (covers, { authenticatorData, clientDataJSON, signature }) {
  return { covers: [...covers], authenticator_data: b64u(authenticatorData), client_data_json: b64u(clientDataJSON), signature: b64u(signature) }
}

// A delegation to a worker's Ed25519 key, from `now` for `lifetime` seconds: { body, payload, id }. Scopes are
// sorted and duplicates dropped; anything the verifier would refuse is refused here first, with a reason to show.
export function delegation ({ identity, membership, root, subject, aud, scopes, now, lifetime }) {
  if (!checkEd25519Key(subject).ok) { // 64 lower-case hex digits, a point on the curve
    throw new Error("the worker's key must be an Ed25519 public key, 64 hex digits")
  }
  if (!isCanonicalOrigin(aud)) throw new Error('the audience must be an origin, such as https://app.example')
  const list = [...new Set(scopes)].sort()
  if (list.length < 1 || list.length > 16 || !list.every((s) => typeof s === 'string' && SCOPE.test(s))) {
    throw new Error('scopes must be 1 to 16 lower-case names')
  }
  if (!Number.isSafeInteger(lifetime) || lifetime < 1 || lifetime > MAX_LIFETIME) throw new Error('the lifetime must be 1 second to 30 days')
  const body = { identity, membership, root, subject, aud, scopes: list, nbf: now, exp: now + lifetime }
  return { body, ...seal('delegation', body) }
}

// What the page hands the worker: the payload and the root's assertion. The worker adds its own consent (D6).
export const handOff = (payload, root) => JSON.stringify({ payload, root })
