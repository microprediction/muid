// The verifier (SPEC §6 F1–F5): a delegation, the root record it names and a fresh head (R9), checked in F5's order
// against configuration fixed at construction.
import { open } from './envelope.js'
import { checkRoot } from './root.js'
import { checkDelegation } from './delegation.js'
import { readWitnessKeys, isWitnessSig, witnessReason } from './attestation.js'
import { isCanonicalOrigin } from './origin.js'
import { refuse } from './bytes.js'

const { apply } = Reflect
const { freeze } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { exec } = RegExp.prototype
const { includes } = Array.prototype

const ID = /^[0-9a-f]{64}$/
const SCOPE = /^[a-z][a-z0-9_.:-]{0,63}$/
const HEAD_KEYS = freeze(['at', 'authority', 'identity', 'memberships'])
const isId = (x) => typeof x === 'string' && apply(exec, ID, [x]) !== null
const isTime = (x) => isSafeInteger(x) && x >= 0
const has = (list, x) => apply(includes, list, [x])

function readConfig (config) {
  if (typeof config !== 'object' || config === null) return undefined
  const { rpId, origin, audience, witnessKeys, skew, maxLifetime, maxStaleness } = config
  const keys = readWitnessKeys(witnessKeys)
  if (typeof rpId !== 'string' || typeof origin !== 'string' || !isCanonicalOrigin(audience) || keys === undefined ||
    !isTime(skew) || !isTime(maxLifetime) || !isTime(maxStaleness)) return undefined
  return freeze({ rpId, origin, audience, keys: freeze(keys), skew, maxLifetime, maxStaleness })
}

// 1–n distinct ids in ascending order (n = 2 for memberships: settled, then pending; 5 for authority).
function ids (list, max, sorted) {
  if (!isArray(list) || list.length < 1 || list.length > max) return false
  for (let i = 0; i < list.length; i++) {
    if (!isId(list[i])) return false
    if (i > 0 && (sorted ? !(list[i - 1] < list[i]) : list[i - 1] === list[i])) return false
  }
  return true
}

// R9: the head's body if it is a head of its form, signed by a pinned witness key whose window holds its `at`.
function headBody (text, cfg) {
  let r
  try {
    r = open(text, 'head')
  } catch {
    return undefined
  }
  const b = r.body
  let i = 0
  for (const k in b) if (k !== HEAD_KEYS[i++]) return undefined
  if (!isId(b.identity) || !ids(b.memberships, 2, false) || !ids(b.authority, 5, true) || !isTime(b.at)) return undefined
  if (!isWitnessSig(r.sig) || witnessReason(r.sig, r.payload, cfg.keys, b.at, b.at + 1) !== undefined) return undefined
  return b
}

export function verifier (config) {
  const cfg = readConfig(config)
  if (cfg === undefined) throw new TypeError('verifier configuration is not well formed')

  function verifyDelegation (records, call) {
    const { now, scope, revoked } = typeof call === 'object' && call !== null ? call : {}
    if (!isTime(now) || typeof scope !== 'string' || apply(exec, SCOPE, [scope]) === null || !isArray(revoked)) {
      throw new TypeError('call must hold now, a scope and a revoked list')
    }
    let given
    try {
      const { delegation, root, head } = records // a primitive gives undefined fields; null and undefined throw
      given = { delegation, root, head }
    } catch {
      return refuse('head') // records that cannot be read hold no head
    }
    const h = headBody(given.head, cfg)
    if (h === undefined) return refuse('head')
    if (h.at < now - cfg.maxStaleness || h.at > now + cfg.skew) return refuse('stale')
    const r = checkRoot(given.root, { rpId: cfg.rpId })
    if (!r.ok) return refuse('root-record')
    const d = checkDelegation(given.delegation, { rootKey: r.key, rpId: cfg.rpId, origin: cfg.origin, now,
      skew: cfg.skew, maxLifetime: cfg.maxLifetime })
    if (!d.ok) return d
    const b = d.body
    if (h.identity !== b.identity) return refuse('identity')
    if (!has(h.memberships, b.membership)) return refuse('membership')
    if (!has(h.authority, b.root)) return refuse('authority')
    const n = revoked.length
    // Stryker disable next-line EqualityOperator: equivalent; one more step reads undefined, never an id
    for (let i = 0; i < n; i++) if (revoked[i] === d.id) return refuse('revoked')
    if (b.aud !== cfg.audience) return refuse('audience')
    if (!has(b.scopes, scope)) return refuse('scope')
    return d
  }

  return freeze({ verifyDelegation })
}
