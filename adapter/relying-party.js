// A relying party's integration of the pure verifier (issue #21; outside the trusted core). It adds the state the
// verifier leaves to its caller, with the established mechanisms for each:
// - replay: a claim id is consumed by one atomic insert-if-absent, before the protected action runs (as a DPoP
//   server's jti store, RFC 9449 §11.1);
// - head memory: the last head accepted for an identity is passed to the verifier and only ever moves forward (as a
//   TUF client's stored metadata).
// Storage that fails, or reads back corrupt, is refused as `storage`; the protected action then does not run.
import { open } from '../src/envelope.js'

const refusal = (reason) => Object.freeze({ ok: false, reason })

// The identity and time a presented head claims, for looking up and advancing the memory. Unverified until the
// verifier accepts the records; undefined if the head cannot be read.
function headFields (text) {
  try {
    const { identity, at } = open(text, 'head').body
    if (typeof identity === 'string' && Number.isSafeInteger(at)) return { identity, at }
  } catch { /* unreadable: not looked up */ }
  return undefined
}

export function relyingParty ({ verifier, store }) {
  // Verify with the stored last head (none when undefined). A stored head the verifier cannot read is corrupt
  // storage, unless the call is itself malformed: then verifying without it throws too, and that programming error
  // propagates. Anything else the verifier throws propagates.
  async function verify (method, given, call) {
    const fields = headFields(given?.head)
    let lastHead
    if (fields !== undefined) {
      try {
        lastHead = await store.lastHead(fields.identity)
      } catch {
        return { r: refusal('storage') }
      }
    }
    let r
    try {
      r = verifier[method](given, { ...call, lastHead })
    } catch (e) {
      if (!(e instanceof TypeError)) throw e
      verifier[method](given, call)
      return { r: refusal('storage') }
    }
    if (!r.ok) return { r: refusal(r.reason) } // one shape for every refusal the adapter returns
    try {
      await store.advanceHead(fields.identity, given.head, fields.at)
    } catch {
      return { r: refusal('storage') }
    }
    return { r }
  }

  // A delegation alone (a request that carries no claim): verified, and the head remembered.
  async function acceptDelegation (given, call) {
    return (await verify('verifyDelegation', given, call)).r
  }

  // A claim: verified, consumed atomically, and only then `action(result)` run, once. If the action fails, the claim
  // stays consumed and the error propagates: the delegate makes a new claim.
  async function acceptClaim (given, call, action) {
    const { r } = await verify('verifyClaim', given, call)
    if (!r.ok) return r
    let fresh
    try {
      fresh = await store.consume(r.id, r.until)
    } catch {
      return refusal('storage')
    }
    if (!fresh) return refusal('replay')
    const value = await action(r)
    return Object.freeze({ ok: true, id: r.id, until: r.until, body: r.body, delegation: r.delegation, value })
  }

  return Object.freeze({ acceptDelegation, acceptClaim })
}
