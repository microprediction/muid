// Executable model of the verifier's time and revocation rules for one delegation (SPEC §6 F5 and F6, D1, D2, R9,
// R10, decision 10 for heads of one second), written from the spec's text rather than from src/verifier.js, so that
// the two can be compared. One identity, one root, one membership: the head's memberships and authority always hold
// the delegation's, so `identity`, `membership` and `authority` never refuse here; the records' shapes, signatures,
// audience and scope are taken as valid. Times are integers; a witness key is { nbf, exp }, its window [nbf, exp).
//
// A call: { now, d: { nbf, exp }, head: { at, key, revoked }, logged: { at, key } | null, revoked, minHeadAt, last }
// where `revoked` lists hold 'D' (the delegation's id), 'S' (its subject key) or other entries, and `last`, when
// present, is { at, revoked }: the newest head the relying party has accepted for the identity.

const holds = (key, t) => key.nbf <= t && t < key.exp
const lacksSome = (a, b) => b.some((x) => !a.includes(x)) // a lacks one of b's entries

// F5's head checks (F6): 'head', 'stale', 'equivocation', or null when the head may be used.
export function headReason (config, { now, head, minHeadAt = 0, last }) {
  const { skew, maxStaleness } = config
  if (!holds(head.key, head.at) || !holds(head.key, now)) return 'head'
  if (now - head.at > maxStaleness || head.at - now > skew || head.at < minHeadAt || (last && head.at < last.at)) return 'stale'
  // Decision 10, heads of one second with the same memberships: the witness only adds revocations within a second,
  // so a head lacking one of the last head's was signed before it ('stale'), unless each lacks one of the other's.
  if (last && head.at === last.at && lacksSome(head.revoked, last.revoked)) {
    return lacksSome(last.revoked, head.revoked) ? 'equivocation' : 'stale'
  }
  return null
}

// The first reason verifyDelegation refuses with, or 'ok'.
export function decide (config, call) {
  const { skew, maxLifetime } = config
  const { now, d, head, logged, revoked, last } = call
  const h = headReason(config, call)
  if (h) return h
  if (d.exp <= d.nbf || d.exp - d.nbf > maxLifetime) return 'lifetime' // D2, D7
  if (now < d.nbf - skew) return 'not-yet' // D1
  if (now >= d.exp) return 'expired'
  // In the head's revoked list, the call's, or the last head's: a later head may have let an entry lapse (R10).
  const named = (list) => list.includes('D') || list.includes('S')
  if (named(head.revoked) || named(revoked) || (last && named(last.revoked))) return 'revoked'
  // R10: the witness's logged record, signed in its key's window, within the delegation's window.
  if (!logged || !holds(logged.key, logged.at) || logged.at < d.nbf - skew || logged.at >= d.exp) return 'logged'
  return 'ok'
}

// Decision 10's order for two heads of one identity and the same memberships, as the relying party's memory uses it
// (§7): the later `at`, or of one `at` the one holding every revocation of the other. Two that each lack one of the
// other's are not ordered.
export const follows = (h, l) => h.at > l.at || (h.at === l.at && !lacksSome(h.revoked, l.revoked))
