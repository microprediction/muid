// A witness's server (or anything between it and a reader) that withholds what the witness holds, or serves part of
// it as it was earlier, can show a reader only the past: over honest histories of an added root, a recovery
// cancelled and a recovery matured, every such view is refused or is the state the identity honestly had at some
// step of that history. No view is of a state that never was (R8, R11). What a witness signs falsely is another
// matter: tests/verifier/R9-equivocation.test.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { membership, envelope } from '../impl.mjs'
import { w, IDENTITY, BASE, WINDOW, start, signed, rootText, rootId, admitAll, state, M2 } from '../witness/fixtures.mjs'
import { partySigned, commitmentOf } from './translate.mjs'

const { MIN_RECOVERY_WINDOW: MIN } = membership
const mId = (body) => envelope.seal('membership', body).id
const ids = (...letters) => letters.map(rootId).sort()
const T0 = BASE + WINDOW
function admitWith (held, items) {
  for (const [type, text, root] of items) {
    const r = w.admit(held, type, text, root)
    assert.equal(r.ok, true, `refused ${type}: ${r.reason}`)
    held = r.held
  }
  return held
}
// Each history is what the witness held after each step.
const steps = (first, ...moves) => moves.reduce((H, move) => [...H, move(H.at(-1))], first)
const at = (now) => (held) => w.advance(held, now).held

const B2 = { identity: IDENTITY, prev: IDENTITY, epoch: 2, roots: ids('a'), recovery: { parties: [commitmentOf('g')], threshold: 1, window: MIN } }
const R = { identity: IDENTITY, prev: mId(B2), epoch: 3, roots: ids('n') }
// Designated and settled; the party and then the new root sign the recovery; notice is given.
const noticed = () => steps([start()],
  (h) => admitAll(h, [['membership', signed('membership', B2, 'a')]]), at(BASE), at(T0),
  (h) => admitWith(h, [['membership', partySigned('membership', R, 'g'), rootText('g')]]),
  (h) => admitWith(h, [['root', rootText('n')], ['membership', signed('membership', R, 'n')]]),
  at(T0 + 5))
const HISTORIES = {
  'a root added': steps([start()],
    (h) => admitAll(h, [['membership', signed('membership', M2, 'a')]]),
    (h) => admitAll(h, [['root', rootText('b')], ['membership', signed('membership', M2, 'b')]]),
    at(BASE), at(T0)),
  'a recovery cancelled': steps(noticed(),
    (h) => admitAll(h, [['cancel', signed('cancel', { identity: IDENTITY, record: mId(R) }, 'a')]]),
    at(T0 + 6), at(T0 + 6 + MIN + 1)),
  'a recovery matured': steps(noticed(), at(T0 + 5 + MIN), at(T0 + 5 + MIN + 1), at(T0 + 5 + MIN + WINDOW + 1))
}
const lists = (held) => Object.keys(held).filter((k) => Array.isArray(held[k]))
const without = (list, ...gone) => list.filter((_, i) => !gone.includes(i))

// Every view with one of the held texts withheld (of the last step, with two), or with one of its lists as it was
// at another step.
function * views (H) {
  for (const [j, held] of H.entries()) {
    const each = lists(held).flatMap((k) => held[k].map((_, i) => [k, i]))
    for (const [n, [k, i]] of each.entries()) {
      yield [`step ${j} without ${k}[${i}]`, { ...held, [k]: without(held[k], i) }]
      if (j < H.length - 1) continue // two at once: of the last step, which holds everything
      for (const [k2, i2] of each.slice(n + 1)) {
        yield [`step ${j} without ${k}[${i}] and ${k2}[${i2}]`, k === k2 ? { ...held, [k]: without(held[k], i, i2) } : { ...held, [k]: without(held[k], i), [k2]: without(held[k2], i2) }]
      }
    }
    for (const k of lists(held)) for (const [j2, other] of H.entries()) if (j2 !== j) yield [`step ${j} with ${k} as at step ${j2}`, { ...held, [k]: other[k] }]
  }
}
const shown = (s) => JSON.stringify(s)

for (const [name, H] of Object.entries(HISTORIES)) {
  test(`${name}: a view with texts withheld, or a list as it was at another step, is refused or is a state the identity had`, () => {
    const had = new Set(H.map((held) => shown(state(held))))
    let n = 0
    let refused = 0
    const seen = new Set(H.map(shown)) // a view that is a step of the history itself, or one already read, is not read again
    for (const [what, view] of views(H)) {
      if (seen.has(shown(view))) continue
      seen.add(shown(view))
      n++
      const s = state(view)
      if (!s.ok) { refused++; continue }
      assert.equal(had.has(shown(s)), true, `${what}: ${shown(s)}`)
    }
    // Anti-vacuity: many views, some refused and most read; and the history itself passes through several states.
    assert.equal(n > 25, true, `${n} views`)
    assert.equal(refused > 0 && refused < n / 2, true, `${refused} of ${n} refused`)
    assert.equal(had.size >= 3, true, `${had.size} states`)
  })
}

test('the histories are what they are named for (anti-vacuity)', () => {
  const last = (name) => state(HISTORIES[name].at(-1))
  assert.deepEqual([last('a root added').epoch, last('a root added').roots], [2, ids('a', 'b')])
  assert.deepEqual([last('a recovery cancelled').epoch, last('a recovery cancelled').roots, last('a recovery cancelled').recovering], [2, ids('a'), null])
  assert.deepEqual([last('a recovery matured').epoch, last('a recovery matured').roots, last('a recovery matured').authority], [3, ids('n'), ids('n')])
  assert.equal(HISTORIES['a recovery matured'].some((held) => state(held).recovering !== null), true, 'it was under notice on the way')
})
