// A relying party's integration of the pure verifier (issue #21; outside the trusted core). It adds the state the
// verifier leaves to its caller, with the established mechanism for each:
// - replay: a claim id is consumed by one atomic insert-if-absent, before the protected action runs (as a DPoP
//   server's jti store, RFC 9449 §11.1);
// - head memory: the last head accepted for an identity is passed to the verifier and only ever moves forward (as a
//   TUF client's stored metadata).
// The records are verified inside one store transaction, against the memory as it stands there, which then advances
// the head and consumes the claim: a database store holds its write lock for one verification. Storage that fails is
// refused as `storage`, and the protected action does not run.
import { open } from '../src/envelope.js'

const refusal = (reason) => Object.freeze({ ok: false, reason })

// The call's fields, each read once (inherited ones too, as the verifier reads them), into a plain object to which
// the adapter adds what it remembers. A call that is not an object is a programming error.
function readCall (call) {
  const { now, scope, request, revoked, minHeadAt } = call
  return { now, scope, request, revoked, minHeadAt }
}

// The presented records, each read once: what is verified is what is remembered. Undefined if reading throws.
function readGiven (given) {
  try {
    const { claim, delegation, root, head } = given // null and undefined throw; a primitive gives no fields
    return { claim, delegation, root, head }
  } catch { /* refused by the verifier */ }
  return undefined
}

export function relyingParty ({ verifier, store }) {
  // Verify against the remembered { head, at }, if any. A stored head the verifier cannot read (corrupt, or signed
  // by a witness key since removed from its configuration) still bounds rollback: its time becomes minHeadAt. A
  // malformed call has already thrown in the check before the transaction; anything the verifier throws other than a
  // TypeError propagates.
  function verifyWith (method, given, call, stored) {
    if (stored === undefined) return verifier[method](given, call)
    try {
      return verifier[method](given, { ...call, lastHead: stored.head })
    } catch (e) {
      if (!(e instanceof TypeError)) throw e
      if (!Number.isSafeInteger(stored.at) || stored.at < 0) return refusal('storage')
      return verifier[method](given, { ...call, minHeadAt: Math.max(call.minHeadAt ?? 0, stored.at) }) // call checked above
    }
  }

  async function accept (method, records, rawCall) {
    const call = readCall(rawCall)
    const given = readGiven(records)
    // Records refused without memory are refused before the transaction, so they never wait for or hold its lock.
    // Memory only adds refusals; what passes here is verified again inside, against the memory as it stands there.
    const pre = verifier[method](given, call)
    if (!pre.ok) return refusal(pre.reason)
    const fields = open(given.head, 'head').body // { identity, at }: a head the verifier has just accepted
    let outcome
    try {
      outcome = await store.transaction((tx) => {
        const stored = tx.lastHead(fields.identity) // the store's: a failure here is refused as storage
        let r
        try {
          r = verifyWith(method, given, call, stored)
        } catch (e) {
          return { thrown: e } // the verifier's, not the store's: rethrown below
        }
        if (!r.ok) return refusal(r.reason)
        tx.advanceHead(fields.identity, given.head, fields.at)
        if (method === 'verifyClaim' && !tx.consume(r.id, r.until)) return refusal('replay')
        return r
      })
    } catch {
      return refusal('storage')
    }
    if (outcome.thrown !== undefined) throw outcome.thrown
    return outcome
  }

  // A delegation alone (a request that carries no claim): verified, and the head remembered.
  const acceptDelegation = (given, call) => accept('verifyDelegation', given, call)

  // A claim: verified, consumed atomically, and only then `action(result)` run, once. If the action fails, the claim
  // stays consumed and the error propagates: the delegate makes a new claim.
  async function acceptClaim (given, call, action) {
    const r = await accept('verifyClaim', given, call)
    if (!r.ok) return r
    const value = await action(r)
    return Object.freeze({ ok: true, id: r.id, until: r.until, body: r.body, delegation: r.delegation, value })
  }

  return Object.freeze({ acceptDelegation, acceptClaim })
}
