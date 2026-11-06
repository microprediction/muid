// The membership witness's decisions (SPEC R3–R5, R8's admission, R9's heads): pure functions over the records it
// holds for one identity, outside the trusted core. model/settled.mjs's `witness` is its specification. Whether a
// record it signs would be followed is decided by the core's own membershipState, never by a second implementation
// of R1: an anchor is kept only if, with it, verifiers see that record pending (R3: "applies R1 exactly as verifiers
// do"). Storage, the network and the transparency log are the service's; the signing key is held by `sign`.
import { open, seal, wrap, signedBytes, EnvelopeError } from '../src/envelope.js'
import { checkRoot, identityOf } from '../src/root.js'
import { checkRootAssertion } from '../src/assertion.js'
import { membershipState, headOf, MAX_RECORDS } from '../src/membership.js'
import { checkDelegation } from '../src/delegation.js'
import { checkEd25519 } from '../src/ed25519.js'
import { readWitnessKeys, onlyKeys, isHex } from '../src/attestation.js'
import { refuse, accept } from '../src/bytes.js'

const { freeze, hasOwn } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { isRefusal } = EnvelopeError

const ID = /^[0-9a-f]{64}$/
// Decision 12's quota: live revocations counted against one root (5 roots × 12 < the 64 a head carries).
const QUOTA = 12
// Tombstones a root may hold for one prev: its replaced proposals, whose resubmission is refused.
const TOMBSTONES = 16
// The record types anyone may submit, and the list each is held in (R8's grouping).
const LISTS = freeze({ __proto__: null, root: 'roots', membership: 'memberships', contest: 'contests', freeze: 'freezes' })
const SHAPES = freeze({
  __proto__: null,
  membership: (b) => onlyKeys(b, ['epoch', 'identity', 'prev', 'roots']) && rootsOk(b.roots),
  contest: (b) => onlyKeys(b, ['identity', 'record']),
  freeze: (b) => onlyKeys(b, ['identity', 'membership']),
})

// 1–5 root ids, strictly ascending (R1's record form).
function rootsOk (roots) {
  if (!isArray(roots) || roots.length < 1 || roots.length > 5) return false
  for (let i = 0; i < roots.length; i++) if (!isHex(ID, roots[i]) || (i > 0 && !(roots[i - 1] < roots[i]))) return false
  return true
}

const isTime = (x) => isSafeInteger(x) && x >= 0
const add = (held, list, text) => freeze({ ...held, [list]: freeze([...held[list], text]) })
const { includes } = Array.prototype
const has = (list, x) => includes.call(list, x) // decoded arrays have no prototype

export function witness (config) {
  const { rpId, origin, witnessKeys, key, sign, contestWindow, skew, maxLifetime } = config // null or undefined throws here
  const keys = readWitnessKeys(witnessKeys)
  if (typeof rpId !== 'string' || typeof origin !== 'string' || !keys?.some((k) => k.key === key) ||
    typeof sign !== 'function' || !isSafeInteger(contestWindow) || contestWindow < 1 || !isTime(skew) || !isTime(maxLifetime)) {
    throw new TypeError('configuration must hold rpId, origin, witnessKeys, a key among them, sign, a positive contestWindow, skew and maxLifetime')
  }
  const stateOf = (held) => membershipState(held, { identity: held.identity, rpId, origin, witnessKeys: keys })

  // A record signed by the witness. A signature that does not verify under the witness's key is a fault of `sign`.
  function make (type, body) {
    const { payload } = seal(type, body)
    const signature = sign(signedBytes(payload))
    if (!checkEd25519(signature, signedBytes(payload), key).ok) throw new Error('sign gave no valid signature under the witness key')
    return wrap(payload, { signature, witness: key })
  }

  // The held root records' ids and keys.
  function rootKeys (held) {
    const out = new Map()
    for (const t of held.roots) {
      const r = checkRoot(t, { rpId })
      out.set(r.id, r.key)
    }
    return out
  }

  // The roots of a membership in the state: a held record's own, or, for the identity id (epoch 1), its first root.
  function rootsOf (held, id) {
    for (const t of held.memberships) {
      const m = open(t, 'membership')
      if (m.id === id) return m.body.roots
    }
    return [...rootKeys(held).keys()].filter((r) => identityOf(r) === held.identity)
  }

  function empty (identity) {
    if (!isHex(ID, identity)) throw new TypeError('identity must be an id')
    const none = freeze([])
    return freeze({ identity, roots: none, memberships: none, contests: none, freezes: none, anchors: none, settlements: none, revocations: none, replaced: none })
  }

  // R8's admission: { ok, held } with the record added (or already held), or a refusal; the holding is not changed.
  function admit (held, type, text) {
    if (!hasOwn(LISTS, type)) {
      seal(type, {}) // throws for a type that does not exist
      return refuse('type')
    }
    const list = LISTS[type]
    if (has(held[list], text)) return accept({ held })
    if (held[list].length >= MAX_RECORDS) return refuse('full')
    if (type === 'root') return admitRoot(held, text)
    let r
    try {
      r = open(text, type)
    } catch (e) {
      return refuse(isRefusal(e) ? e.reason : 'envelope-encoding')
    }
    const b = r.body
    if (!SHAPES[type](b) || !onlyKeys(r.sig, ['assertion', 'root'])) return refuse('shape')
    const s = against(held, b)
    if (!s.ok) return s
    const signer = r.sig.root
    // One envelope per record and signer: another (an assertion covering other records too) adds nothing.
    if (held[list].some((t) => { const x = open(t, type); return x.id === r.id && x.sig.root === signer })) return accept({ held })
    let roots
    if (type === 'membership') {
      if (b.prev !== s.membership) return refuse('prev')
      if (b.epoch !== s.epoch + 1) return refuse('epoch')
      // A root the record adds signs only once a strict majority of the effective membership's roots has.
      const added = !has(s.roots, signer) && has(b.roots, signer)
      roots = added && 2 * signersOf(held, r.id, s.roots) > s.roots.length ? [signer] : s.roots
    } else if (type === 'contest') {
      if (!s.pending || b.record !== s.membership) return refuse('record')
      roots = rootsOf(held, s.settled)
    } else {
      if (b.membership !== s.settled && b.membership !== s.membership) return refuse('membership')
      roots = b.membership === s.membership ? s.roots : rootsOf(held, s.settled)
    }
    if (!has(roots, signer)) return refuse('signer')
    const k = rootKeys(held).get(signer)
    if (k === undefined) return refuse('root-missing')
    if (!checkRootAssertion(r.sig.assertion, { record: r.id, rpId, origin, key: k }).ok) return refuse('signature')
    // W0: one prompt cannot both propose a change and end the identity by contesting it — the record itself, or the
    // pending record it would follow.
    const covers = r.sig.assertion.covers
    const shared = type === 'contest'
      ? has(covers, b.record) || held.memberships.some((t) => { const x = open(t, 'membership'); return x.body.prev === b.record && has(covers, x.id) })
      : type === 'membership' && (has(covers, contestOf(held.identity, r.id)) || has(covers, contestOf(held.identity, b.prev)))
    if (shared) return refuse('covers')
    if (type !== 'membership') return accept({ held: add(held, list, text) })
    // One proposal per root and prev: a root's later proposal replaces its earlier one, so no root can fill the list;
    // root records only a replaced proposal named go with it (the first root, and every held record's roots, stay).
    // A replaced (record, signer) is kept as a tombstone, so that no one holding the withdrawn envelope can bring it
    // back; tombstones of an earlier prev are dropped, since a proposal for it is refused anyway.
    const tombs = held.replaced.filter((x) => x.prev === b.prev)
    if (tombs.some((x) => x.record === r.id && x.signer === signer)) return refuse('replaced')
    const mine = (x) => x.sig.root === signer && x.body.prev === b.prev
    const gone = held.memberships.map((t) => open(t, 'membership')).filter(mine)
    if (gone.length > 0 && tombs.filter((x) => x.signer === signer).length >= TOMBSTONES) return refuse('quota')
    const replaced = freeze([...tombs, ...gone.map((x) => freeze({ record: x.id, signer, prev: b.prev }))])
    const memberships = freeze([...held.memberships.filter((t) => !mine(open(t, 'membership'))), text])
    const named = (id) => identityOf(id) === held.identity || memberships.some((t) => has(open(t, 'membership').body.roots, id))
    const kept = freeze(held.roots.filter((t) => named(checkRoot(t, { rpId }).id)))
    return accept({ held: freeze({ ...held, memberships, roots: kept, replaced }) })
  }

  // The id of the contest of membership record `record`: the same for every signer.
  const contestOf = (identity, record) => seal('contest', { identity, record }).id

  // The state a submitted record is admitted against; a refusal for another identity's record, or an unknown or
  // dead identity.
  function against (held, b) {
    if (b.identity !== held.identity) return refuse('identity')
    const s = stateOf(held)
    return s.dead ? refuse('dead') : s // a refusal (an unknown identity) is passed on as it is
  }

  // A root record: the identity's first root, or one a held membership record names.
  function admitRoot (held, text) {
    const r = checkRoot(text, { rpId })
    if (!r.ok) return r
    if (identityOf(r.id) !== held.identity && !held.memberships.some((t) => has(open(t, 'membership').body.roots, r.id))) {
      return refuse('root-unnamed')
    }
    return accept({ held: add(held, 'roots', text) })
  }

  // How many of `roots` have signed the held membership record `id` (every held signature verified on admission).
  function signersOf (held, id, roots) {
    const seen = new Set()
    for (const t of held.memberships) {
      const m = open(t, 'membership')
      if (m.id === id && has(roots, m.sig.root)) seen.add(m.sig.root)
    }
    return seen.size
  }

  // What the witness signs at `now`, as the model's witness: { held, signed: [{ type, text }] }.
  function advance (held, now) {
    if (!isTime(now)) throw new TypeError('now must be a non-negative integer')
    const signed = []
    const sign1 = (type, text) => { signed[signed.length] = freeze({ type, text }) }
    for (;;) {
      // The witness's own view leaves out contest anchors, so that a contested epoch can be settled as contested.
      const contests = new Map()
      for (const t of held.contests) {
        const c = open(t, 'contest')
        contests.set(c.body.record, c.id)
      }
      const anchors = held.anchors.map((t) => open(t, 'anchor').body)
      const isContest = (a) => [...contests.values()].includes(a.record)
      const own = freeze({ ...held, anchors: held.anchors.filter((t, i) => !isContest(anchors[i])) })
      // A dead or unknown identity has no settled membership and nothing pending: nothing is signed for it.
      const s = stateOf(own)
      if (!s.pending) {
        // R3: a held successor of the settled membership that verifiers would see pending. At most one has a strict
        // majority, since each root holds one proposal per prev, so the order they are tried in does not matter.
        const ids = [...new Set(held.memberships.map((t) => open(t, 'membership'))
          // Stryker disable next-line ConditionalExpression,MethodExpression: equivalent; the check below refuses a record of another prev, and this bounds the work
          .filter((m) => m.body.prev === s.settled).map((m) => m.id))]
        let found
        for (const x of ids) {
          const text = make('anchor', { identity: held.identity, record: x, at: now })
          if (stateOf(add(own, 'anchors', text)).membership === x) { found = text; break }
        }
        if (found === undefined) break
        held = add(held, 'anchors', found)
        sign1('anchor', found)
        continue
      }
      const at = anchors.find((a) => a.record === s.membership).at
      const contest = contests.get(s.membership)
      const contested = anchors.some((a) => a.record === contest) // false when there is no contest
      if (now < at + contestWindow) {
        // R5: a contest of the pending record, anchored only if verifiers then see the identity end.
        if (contest === undefined || contested) break
        const text = make('anchor', { identity: held.identity, record: contest, at: now })
        if (!stateOf(add(held, 'anchors', text)).dead) break
        held = add(held, 'anchors', text)
        sign1('anchor', text)
        continue
      }
      // R4: the window has passed; the settlement is final.
      const text = make('settlement', { identity: held.identity, prev: s.settled, outcome: contested ? 'contested' : s.membership, at: now })
      held = add(held, 'settlements', text)
      sign1('settlement', text) // a contested settlement ends the identity, and the next pass signs nothing
    }
    return freeze({ held, signed: freeze(signed) })
  }

  // R9: the head for what the witness holds at `now`, signed; undefined where headOf gives none.
  function head (held, now) {
    if (!isTime(now)) throw new TypeError('now must be a non-negative integer')
    const s = stateOf(held)
    const body = headOf(s, now, kept(held, now).map((x) => x.target))
    return body === undefined ? undefined : make('head', body)
  }

  // Decision 12, after review round 8: a revocation is kept for the life of the identity, since a delegation may be
  // signed in advance under a membership not yet anchored (W0), so no change of membership bounds what it can affect;
  // one of a delegation id given with that delegation is kept until its expiry plus skew, after which no record it
  // names verifies. `until` is null for the first kind.
  const kept = (held, now) => held.revocations.filter((x) => x.until === null || now < x.until)

  // R9's admission of a revocation `{ identity, target, at }`: signed by a root with authority, or by a delegate for
  // its own key, given with the delegation that makes it a delegate of this identity, so that no one else can add an
  // entry (past 64, no head is signed). One entry per target; entries no longer kept are dropped. Each entry counts
  // against one root, the signer or the delegation's, and a root holds at most QUOTA, so one stolen root cannot
  // fill the 64.
  function revoke (held, text, now, delegation) {
    if (!isTime(now)) throw new TypeError('now must be a non-negative integer')
    let r
    try {
      r = open(text, 'revocation')
    } catch (e) {
      return refuse(isRefusal(e) ? e.reason : 'envelope-encoding')
    }
    const b = r.body
    const bySelf = hasOwn(r.sig, 'signature')
    if (!onlyKeys(b, ['at', 'identity', 'target']) || !isHex(ID, b.target) || !isTime(b.at) ||
      !(bySelf ? onlyKeys(r.sig, ['signature']) && typeof r.sig.signature === 'string' : onlyKeys(r.sig, ['assertion', 'root']) && hasOwn(r.sig, 'root'))) {
      return refuse('shape')
    }
    const s = against(held, b)
    if (!s.ok) return s
    const live = kept(held, now)
    if (live.some((x) => x.target === b.target)) return accept({ held })
    if (live.length >= MAX_RECORDS) return refuse('full')
    let root = r.sig.root
    if (bySelf) {
      if (!delegates(held, s, delegation, now, b.target)) return refuse('delegation')
      if (!checkEd25519(r.sig.signature, signedBytes(r.payload), b.target).ok) return refuse('signature')
      root = named(delegation).body.root
    } else {
      if (!has(s.authority, r.sig.root)) return refuse('signer')
      const k = rootKeys(held).get(r.sig.root)
      if (!checkRootAssertion(r.sig.assertion, { record: r.id, rpId, origin, key: k }).ok) return refuse('signature')
    }
    // A root's revocation of a delegation id may come with that delegation, so that it can lapse with it.
    let until = null
    if (!bySelf && delegation !== undefined) {
      const d = named(delegation)
      if (d === undefined || d.id !== b.target) return refuse('delegation')
      until = d.body.exp + skew
    }
    if (live.filter((x) => x.root === root).length >= QUOTA) return refuse('quota')
    const entry = freeze({ text, target: b.target, until, root })
    return accept({ held: freeze({ ...held, revocations: freeze([...live, entry]) }) })
  }

  // The delegation record a text holds, or undefined: its id is the hash of its payload, so its fields are the ones named.
  function named (text) {
    try {
      return open(text, 'delegation')
    } catch { /* not a delegation: undefined */ }
  }

  // Whether `delegation` verifies at `now`, is this identity's under its settled or pending membership, and is to `subject`.
  function delegates (held, s, delegation, now, subject) {
    const d = named(delegation)?.body
    if (d === undefined) return false
    const rootKey = rootKeys(held).get(d.root) // held: a root with authority is in a held membership
    // R6: its root has authority now, so no retired or proposed root can add entries.
    return has(s.authority, d.root) && d.identity === held.identity && (d.membership === s.settled || d.membership === s.membership) &&
      d.subject === subject && checkDelegation(delegation, { rootKey, rpId, origin, now, skew, maxLifetime }).ok
  }

  return freeze({ empty, admit, advance, head, revoke })
}
