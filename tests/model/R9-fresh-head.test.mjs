// Open decision 7, as evidence: without a fresh head a stale view gives a retired root authority; with R9's head it
// never does, and the residual is bounded by MAX_STALENESS. Uses the settled model (model/settled.mjs).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluate, history, active } from '../../model/settled.mjs'

const MAX_STALENESS = 2
// What the witness signs on request (R9): the effective authority of the full record set, and when.
const head = (items, at) => { const e = evaluate('a', items); return { authority: e.dead || !active(e) ? [] : e.authority, at } }
// The verifier's rule with R9: a root has authority only if a head no older than MAX_STALENESS says so.
const withHead = (h, now, r) => now - h.at <= MAX_STALENESS && h.authority.includes(r)

// a, then {a, b, c}, then {b, c, d}: the first root a is retired.
const full = history('a', [['a', 'b', 'c'], ['b', 'c', 'd']])
const views = (items) => {
  // Every prefix of the record list: what a network attacker can show by withholding the rest.
  const out = []
  for (let i = 0; i <= items.length; i++) out.push(items.slice(0, i))
  return out
}

test('without a head, some partial view still gives the retired first root authority (the attack)', () => {
  assert.equal(evaluate('a', full).authority.includes('a'), false, 'the full view: a is retired')
  const stale = views(full).filter((v) => { const e = evaluate('a', v); return active(e) && e.authority.includes('a') })
  assert.ok(stale.length > 0, 'a view in which a still has authority exists')
})

test('with a fresh head, the retired root has authority in no view', () => {
  const h = head(full, 100)
  for (const v of views(full)) assert.equal(withHead(h, 100, 'a'), false, `view of ${v.length} items`)
  for (const r of ['b', 'c', 'd']) assert.equal(withHead(h, 100, r), true, r)
})

test('a head from before the retirement is accepted only while it is no older than MAX_STALENESS (the residual)', () => {
  const before = history('a', [['a', 'b', 'c']])
  const old = head(before, 100)
  assert.equal(withHead(old, 100 + MAX_STALENESS, 'a'), true, 'within the bound: the stated residual')
  assert.equal(withHead(old, 100 + MAX_STALENESS + 1, 'a'), false, 'past it: refused')
})
