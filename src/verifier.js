// The verifier (SPEC §6 F1–F5): a delegation, the root record it names and a fresh head (R9), checked in F5's order
// against configuration fixed at construction.
import { open, signedBytes, EnvelopeError } from './envelope.js'
import { checkEd25519 } from './ed25519.js'
import { checkRoot } from './root.js'
import { checkDelegation } from './delegation.js'
import { readWitnessKeys, isWitnessSig, witnessReason } from './attestation.js'
import { isCanonicalOrigin } from './origin.js'
import { refuse, accept } from './bytes.js'

const { apply } = Reflect
const { freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { includes } = Array.prototype
const { isRefusal } = EnvelopeError

const ID = /^[0-9a-f]{64}$/
const SCOPE = /^[a-z][a-z0-9_.:-]{0,63}$/
const HEAD_KEYS = freeze(['at', 'authority', 'identity', 'memberships', 'revoked'])
const MAX_REVOKED = 64
const isId = (x) => typeof x === 'string' && apply(exec, ID, [x]) !== null
const isTime = (x) => isSafeInteger(x) && x >= 0
const has = (list, x) => apply(includes, list, [x])

function readConfig (config) {
  if (typeof config !== 'object' || config === null) return undefined
  const { rpId, origin, audience, witnessKeys, skew, maxLifetime, maxStaleness, maxClaimAge } = config
  const keys = readWitnessKeys(witnessKeys)
  if (typeof rpId !== 'string' || typeof origin !== 'string' || !isCanonicalOrigin(audience) || keys === undefined ||
    !isTime(skew) || !isTime(maxLifetime) || !isTime(maxStaleness) || !isTime(maxClaimAge)) return undefined
  return freeze({ rpId, origin, audience, keys: freeze(keys), skew, maxLifetime, maxStaleness, maxClaimAge })
}

// min–max distinct ids, in ascending order if `sorted` (memberships: settled, then pending).
function ids (list, min, max, sorted) {
  if (!isArray(list) || list.length < min || list.length > max) return false
  for (let i = 0; i < list.length; i++) {
    if (!isId(list[i])) return false
    if (i > 0 && (sorted ? !(list[i - 1] < list[i]) : list[i - 1] === list[i])) return false
  }
  return true
}

// A copy of the list if every entry is an id (a malformed revocation would otherwise fail open), else undefined.
function allIds (list) {
  if (!isArray(list)) return undefined
  // Stryker disable next-line ArrayDeclaration: equivalent; every index is assigned before it is read
  const out = []
  const n = list.length
  for (let i = 0; i < n; i++) {
    const x = list[i]
    if (!isId(x)) return undefined
    out[i] = x
  }
  return freeze(out)
}

// R9: the head's body if it is a head of its form, signed by a pinned witness key whose window holds its `at` and now.
function headBody (text, cfg, now) {
  let r
  try {
    r = open(text, 'head')
  } catch {
    return undefined
  }
  const b = r.body
  let i = 0
  for (const k in b) if (k !== HEAD_KEYS[i++]) return undefined
  if (!isId(b.identity) || !ids(b.memberships, 1, 2, false) || !ids(b.authority, 1, 5, true) ||
    !ids(b.revoked, 0, MAX_REVOKED, true) || !isTime(b.at)) return undefined
  // Stryker disable next-line EqualityOperator: equivalent; at now === at both branches give the same value
  const until = (now > b.at ? now : b.at) + 1
  if (!isWitnessSig(r.sig) || witnessReason(r.sig, r.payload, cfg.keys, b.at, until) !== undefined) return undefined
  return b
}

const CLAIM_KEYS = freeze(['at', 'data', 'delegation', 'request', 'scope'])
const SIG128 = /^[0-9a-f]{128}$/

// The call's fields, each read once (the revoked list copied); a claim's call also names the request it is for.
function readCall (call, claim) {
  const { now, scope, request, revoked, minHeadAt = 0 } = typeof call === 'object' && call !== null ? call : {}
  const list = allIds(revoked)
  if (!isTime(now) || typeof scope !== 'string' || apply(exec, SCOPE, [scope]) === null || !isTime(minHeadAt) ||
    list === undefined || (claim && typeof request !== 'string')) {
    throw new TypeError('call must hold now, a scope and a revoked list')
  }
  return { now, scope, request, revoked: list, minHeadAt }
}

// The fields of `records`, each read once; undefined if they cannot be read.
function readRecords (records) {
  try {
    const { claim, delegation, root, head } = records // a primitive gives undefined fields; null and undefined throw
    return { claim, delegation, root, head }
  } catch { /* reported by the caller */ }
  return undefined
}

export function verifier (config) {
  const cfg = readConfig(config)
  if (cfg === undefined) throw new TypeError('verifier configuration is not well formed')

  // F5 for a delegation, given its records and the call's fields.
  function check (given, { now, scope, revoked, minHeadAt }) {
    const h = headBody(given.head, cfg, now)
    if (h === undefined) return refuse('head')
    if (h.at < now - cfg.maxStaleness || h.at > now + cfg.skew || h.at < minHeadAt) return refuse('stale')
    const r = checkRoot(given.root, { rpId: cfg.rpId })
    if (!r.ok) return refuse('root-record')
    const d = checkDelegation(given.delegation, { rootKey: r.key, rpId: cfg.rpId, origin: cfg.origin, now,
      skew: cfg.skew, maxLifetime: cfg.maxLifetime })
    if (!d.ok) return d
    const b = d.body
    if (h.identity !== b.identity) return refuse('identity')
    if (!has(h.memberships, b.membership)) return refuse('membership')
    if (!has(h.authority, b.root)) return refuse('authority')
    if (has(h.revoked, d.id) || has(h.revoked, b.subject)) return refuse('revoked')
    const n = revoked.length
    // Stryker disable next-line EqualityOperator: equivalent; one more step reads undefined, never an id
    for (let i = 0; i < n; i++) if (revoked[i] === d.id || revoked[i] === b.subject) return refuse('revoked')
    if (b.aud !== cfg.audience) return refuse('audience')
    if (!has(b.scopes, scope)) return refuse('scope')
    return d
  }

  function verifyDelegation (records, call) {
    const c = readCall(call, false)
    const given = readRecords(records)
    return given === undefined ? refuse('head') : check(given, c)
  }

  // C1: an ephemeral claim, with its delegation verified in full under the claim's scope.
  function verifyClaim (records, call) {
    const c = readCall(call, true)
    const given = readRecords(records)
    let claim
    try {
      claim = open(given.claim, 'claim') // unreadable records throw here too, and are refused below
    } catch (e) {
      return refuse(isRefusal(e) ? e.reason : 'envelope-encoding')
    }
    const b = claim.body
    let i = 0
    for (const k in b) if (k !== CLAIM_KEYS[i++]) return refuse('claim-shape')
    let keys = 0
    for (const k in claim.sig) keys++ // eslint-disable-line no-unused-vars
    if (!isId(b.delegation) || typeof b.scope !== 'string' || apply(exec, SCOPE, [b.scope]) === null ||
      typeof b.request !== 'string' || !isTime(b.at) ||
      typeof b.data !== 'object' || isArray(b.data) || keys !== 1 || typeof claim.sig.signature !== 'string' ||
      apply(exec, SIG128, [claim.sig.signature]) === null) return refuse('claim-shape')
    if (b.scope !== c.scope) return refuse('claim-scope')
    if (b.request !== c.request) return refuse('claim-request')
    const d = check(given, c)
    if (!d.ok) return d
    if (b.delegation !== d.id) return refuse('claim-delegation')
    if (b.at < c.now - cfg.maxClaimAge || b.at > c.now + cfg.skew || b.at < d.body.nbf - cfg.skew ||
      b.at >= d.body.exp) return refuse('claim-time')
    const s = checkEd25519(claim.sig.signature, signedBytes(claim.payload), d.body.subject)
    if (!s.ok) return s
    // Replay inside the window is the caller's to refuse: keep the id until `until`.
    return accept({ id: claim.id, body: b, delegation: freeze({ id: d.id, body: d.body }), until: b.at + cfg.maxClaimAge })
  }

  return freeze({ verifyDelegation, verifyClaim })
}
