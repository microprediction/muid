// The membership witness's decisions (SPEC R3–R5, R8's admission, R9's heads): pure functions over the records it
// holds for one identity, outside the trusted core. model/settled.mjs's `witness` is its specification. Whether a
// record it signs would be followed is decided by the core's own membershipState, never by a second implementation
// of R1: an anchor is kept only if, with it, verifiers see that record pending (R3: "applies R1 exactly as verifiers
// do"). Storage, the network and the transparency log are the service's; the signing key is held by `sign`.
import { open, seal, wrap, signedBytes, EnvelopeError } from '../src/envelope.js'
import { checkRoot, identityOf } from '../src/root.js'
import { checkRootAssertion } from '../src/assertion.js'
import { membershipState, headOf, MAX_RECORDS } from '../src/membership.js'
import { checkEd25519 } from '../src/ed25519.js'
import { readWitnessKeys, onlyKeys, isHex } from '../src/attestation.js'
import { refuse, accept } from '../src/bytes.js'

const { freeze, hasOwn } = Object
const { isArray } = Array
const { isSafeInteger } = Number
const { isRefusal } = EnvelopeError

const ID = /^[0-9a-f]{64}$/
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
  const { rpId, origin, witnessKeys, key, sign, contestWindow } = config // null or undefined throws a TypeError here
  const keys = readWitnessKeys(witnessKeys)
  if (typeof rpId !== 'string' || typeof origin !== 'string' || !keys?.some((k) => k.key === key) ||
    typeof sign !== 'function' || !isSafeInteger(contestWindow) || contestWindow < 1) {
    throw new TypeError('configuration must hold rpId, origin, witnessKeys, a key among them, sign and a positive contestWindow')
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
    return freeze({ identity, roots: none, memberships: none, contests: none, freezes: none, anchors: none, settlements: none })
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
    if (b.identity !== held.identity) return refuse('identity')
    const s = stateOf(held)
    if (!s.ok) return s
    if (s.dead) return refuse('dead')
    const signer = r.sig.root
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
    return accept({ held: add(held, list, text) })
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
        // R3: the lowest id among held successors of the settled membership that verifiers would see pending.
        const ids = [...new Set(held.memberships.map((t) => open(t, 'membership'))
          // Stryker disable next-line ConditionalExpression,MethodExpression: equivalent; the check below refuses a record of another prev, and this bounds the work
          .filter((m) => m.body.prev === s.settled).map((m) => m.id))].sort()
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
  function head (held, now, revoked) {
    if (!isTime(now)) throw new TypeError('now must be a non-negative integer')
    const body = headOf(stateOf(held), now, revoked)
    return body === undefined ? undefined : make('head', body)
  }

  return freeze({ empty, admit, advance, head })
}
