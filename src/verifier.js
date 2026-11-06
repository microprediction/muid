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
const HEAD_KEYS = freeze(['at', 'authority', 'epoch', 'identity', 'memberships', 'revoked'])
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

// R9: the head's body if it is a head of its form, signed by a pinned witness key whose window holds its `at` and now
// (its `at` alone when `now` is undefined, as for a relying party's last head: undefined compares false either way).
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
  if (!isId(b.identity) || !ids(b.memberships, 1, 2, false) || !ids(b.authority, 1, 5, true) || !isTime(b.at) ||
    !ids(b.revoked, 0, MAX_REVOKED, true) || !(isTime(b.epoch) && b.epoch > 0 && b.epoch < 2 ** 32) ||
    (b.epoch === 1) !== (b.memberships[0] === b.identity) || b.memberships[1] === b.identity) return undefined
  // The key's window must hold both the head's time and now, whichever comes first.
  // Stryker disable next-line EqualityOperator: equivalent; at now === at both branches give the same value
  const from = now < b.at ? now : b.at
  // Stryker disable next-line EqualityOperator: equivalent; at now === at both branches give the same value
  const until = (now > b.at ? now : b.at) + 1
  if (!isWitnessSig(r.sig) || witnessReason(r.sig, r.payload, cfg.keys, from, until) !== undefined) return undefined
  return b
}

const CLAIM_KEYS = freeze(['at', 'data', 'delegation', 'request', 'scope'])
const SIG128 = /^[0-9a-f]{128}$/

// The call's fields, each read once (the revoked list copied); a claim's call also names the request it is for.
function readCall (call, claim, cfg) {
  const { now, scope, request, revoked, minHeadAt = 0, lastHead } = typeof call === 'object' && call !== null ? call : {}
  const list = allIds(revoked)
  const last = headBody(lastHead, cfg, undefined) // undefined when no last head is given
  if (!isTime(now) || typeof scope !== 'string' || apply(exec, SCOPE, [scope]) === null || !isTime(minHeadAt) ||
    list === undefined || (claim && typeof request !== 'string') || (lastHead !== undefined && last === undefined)) {
    throw new TypeError('call must hold now, a scope and a revoked list')
  }
  return { now, scope, request, revoked: list, minHeadAt, last }
}

const within = (a, b) => { for (let i = 0; i < a.length; i++) if (!has(b, a[i])) return true; return false } // a ⊄ b

// Decision 10: `h` cannot honestly follow `l`: at one `at` it drops a revocation, an epoch falls, an id stands at two
// epochs (R1, R3), or authority does not follow the memberships (R6: unchanged; shrinking to pending; growing as it
// settles alone). Index reads only.
function forked (l, h) {
  // Within one second the witness only adds revocations (an entry lapses with time).
  if (h.at === l.at && within(l.revoked, h.revoked)) return true
  const lm = l.memberships
  const hm = h.memberships
  if (h.epoch < l.epoch || h.epoch + hm.length < l.epoch + lm.length) return true
  // Stryker disable next-line EqualityOperator: equivalent; j = hm.length matters only if the top epoch fell (above)
  for (let i = 0; i < lm.length; i++) for (let j = 0; j < hm.length; j++) if ((l.epoch + i === h.epoch + j) !== (lm[i] === hm[j])) return true
  if (h.epoch === l.epoch) return within(h.authority, l.authority) || (hm.length === lm.length && within(l.authority, h.authority))
  return h.epoch === l.epoch + 1 && lm.length === 2 && hm.length === 1 && within(l.authority, h.authority)
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

  // F5's head checks: the head's form, signature and window (R9), its freshness, and its consistency with the last
  // head accepted. Gives the head's body, or the refusal.
  function checkHead (text, { now, minHeadAt, last }) {
    const h = headBody(text, cfg, now)
    if (h === undefined) return refuse('head')
    if (h.at < now - cfg.maxStaleness || h.at > now + cfg.skew || h.at < minHeadAt || (last && h.at < last.at)) {
      return refuse('stale')
    }
    if (last && last.identity !== h.identity) return refuse('identity')
    // Heads of one `at` may be signed in either order: such a pair is evidence only if inconsistent both ways.
    if (last && forked(last, h)) return refuse(h.at === last.at && !forked(h, last) ? 'stale' : 'equivocation')
    return h
  }

  // F5 for a delegation, given its records and the call's fields.
  function check (given, c) {
    const { now, scope, revoked } = c
    const h = checkHead(given.head, c)
    if (h.ok === false) return h // a head body has no `ok`
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

  // F6: a head alone, under the same call: { ok, identity, at }, or F5's head refusal. A relying party may remember
  // any head that verifies, whatever else a request carries.
  function verifyHead (head, call) {
    const h = checkHead(head, readCall(call, false, cfg))
    return h.ok === false ? h : accept({ identity: h.identity, at: h.at })
  }

  function verifyDelegation (records, call) {
    const c = readCall(call, false, cfg)
    const given = readRecords(records)
    return given === undefined ? refuse('head') : check(given, c)
  }

  // C1: an ephemeral claim, with its delegation verified in full under the claim's scope.
  function verifyClaim (records, call) {
    const c = readCall(call, true, cfg)
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
    // Replay inside the window is the caller's to refuse: keep the id until `until`, the first time it is refused.
    return accept({ id: claim.id, body: b, delegation: freeze({ id: d.id, body: d.body }), until: b.at + cfg.maxClaimAge + 1 })
  }

  return freeze({ verifyHead, verifyDelegation, verifyClaim })
}
