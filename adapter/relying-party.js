// A relying party's integration of the pure verifier (issue #21; outside the trusted core). It adds the state the
// verifier leaves to its caller, with the established mechanism for each:
// - replay: a claim id is consumed by one atomic insert-if-absent, before the protected action runs (as a DPoP
//   server's jti store, RFC 9449 §11.1);
// - head memory: the last head accepted for an identity is passed to the verifier and only ever moves forward (as a
//   TUF client's stored metadata).
// The records are verified inside one store transaction, against the memory as it stands there, which then advances
// the head and consumes the claim: a database store holds its write lock for one verification. Storage that fails is
// refused as `storage`, and the protected action does not run.
const refusal = (reason) => Object.freeze({ ok: false, reason })

// The call's fields, each read once (inherited ones too, as the verifier reads them), into a plain object to which
// the adapter adds what it remembers. A call that is not an object, or that brings its own lastHead, is a programming
// error: the adapter supplies lastHead from its memory.
function readCall (call) {
  const { now, scope, request, revoked, minHeadAt, lastHead } = call
  if (lastHead !== undefined) throw new TypeError('the adapter supplies lastHead from its memory')
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
  // `check(call)` under the remembered { head, at }, if any. A stored head the verifier cannot read (corrupt, or
  // signed by a witness key since removed from its configuration) still bounds rollback: its time becomes
  // minHeadAt. A malformed call has already thrown in the checks before the transaction; anything the verifier throws
  // other than a TypeError propagates.
  function withMemory (check, call, stored) {
    if (stored === undefined) return check(call)
    try {
      return check({ ...call, lastHead: stored.head })
    } catch (e) {
      if (!(e instanceof TypeError)) throw e
      if (!Number.isSafeInteger(stored.at) || stored.at < 0) return refusal('storage')
      return check({ ...call, minHeadAt: Math.max(call.minHeadAt ?? 0, stored.at) })
    }
  }

  async function accept (method, records, rawCall) {
    const call = readCall(rawCall)
    const given = readGiven(records)
    // Without memory first, outside the lock. Memory only adds refusals, so a request refused here is refused; it
    // takes the lock only to remember its head, when that head verifies and is newer than the memory (F6).
    const pre = verifier[method](given, call)
    const seen = verifier.verifyHead(given?.head, call)
    if (!seen.ok) return refusal(pre.reason)
    if (!pre.ok) {
      let stored
      try {
        stored = await store.lastHead(seen.identity)
      } catch {
        return refusal('storage')
      }
      if (stored !== undefined && stored.at >= seen.at) return refusal(pre.reason)
    }
    let outcome
    try {
      outcome = await store.transaction((tx) => {
        const stored = tx.lastHead(seen.identity) // the store's: a failure here is refused as storage
        let head, r
        try {
          head = withMemory((c) => verifier.verifyHead(given.head, c), call, stored)
          r = withMemory((c) => verifier[method](given, c), call, stored)
        } catch (e) {
          return { thrown: e } // the verifier's, not the store's: rethrown below
        }
        if (head.ok) tx.advanceHead(seen.identity, given.head, seen.at)
        if (!r.ok) return refusal(r.reason)
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
