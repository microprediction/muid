// History, the demo's reader: given an identity's contributions as bundles (a receipt, the cosigned checkpoint and
// inclusion proof from when it was logged, and the claim it names), it keeps those that verify under its own pinned
// services and log configuration (verifyReceipt, C2), with when each existed by. A delegation's expiry does not
// matter here: that is what receipts are for.
import { verifyReceipt } from '../src/receipt.js'

function bytes (h) {
  const out = new Uint8Array(h.length / 2)
  // Stryker disable next-line EqualityOperator: equivalent; a write past the end of a typed array is ignored
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16)
  return out
}

export function history ({ services, log, skew }) {
  // { accepted: [{ service, identity, delegation, claim, at, existedBy }], refused: [{ index, reason }] }
  function verify (identity, bundles, now) {
    const accepted = []
    const refused = []
    // The answer comes from the service: anything but a list is refused as a whole.
    if (!Array.isArray(bundles)) return { accepted, refused: [{ index: null, reason: 'bundles' }] }
    for (let i = 0; i < bundles.length; i++) {
      const b = bundles[i]
      const proof = Array.isArray(b?.proof) && b.proof.every((h) => typeof h === 'string' && /^(?:[0-9a-f]{2})*$/.test(h)) ? b.proof.map(bytes) : undefined
      const r = proof === undefined
        ? { ok: false, reason: 'bundle' }
        : verifyReceipt({ receipt: b.receipt, checkpoint: b.checkpoint, proof, index: b.index, claim: b.claim }, { services, log, now, skew })
      if (r.ok && r.identity !== identity) refused.push({ index: i, reason: 'identity' })
      else if (r.ok) accepted.push({ service: r.service, identity: r.identity, delegation: r.delegation, claim: r.claim, at: r.at, existedBy: r.existedBy })
      else refused.push({ index: i, reason: r.reason })
    }
    return { accepted, refused }
  }
  return Object.freeze({ verify })
}
