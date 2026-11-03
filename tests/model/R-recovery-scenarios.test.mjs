// R1–R5 explored against a thief: what one stolen (copied) root can do, and what the owner can do afterwards.
// The owner keeps every root, since theft copies a passkey; each side also has one fresh root of its own.
// Bounds: one thief move here (deeper runs are in model/README.md). Outcomes are pinned, including the bad ones.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { analyse, history, evaluate } from '../../model/recovery.mjs'

function run (epochs, roots, stolen, thiefDepth = 1) {
  const h = history('a', epochs)
  return analyse({ genesis: 'a', history: h, owner: new Set([...roots, 'o']), thief: new Set([...stolen, 't']),
    universe: [...roots, 'o', 't'], maxEpoch: epochs.length + 3, thiefDepth })
}

test('one root, stolen: the thief takes over in one move; the owner can still end the identity, not reclaim it', () => {
  const r = run([], ['a'], ['a'])
  assert.deepEqual(evaluate('a', r.takeover).roots, ['t'])
  assert.equal(r.cannotStop, null)
  assert.ok(r.unrecoverable)
})

test('two roots, the later one stolen: no takeover, no kill; the owner can always stop the thief', () => {
  const r = run([['a', 'b']], ['a', 'b'], ['b'], 2)
  assert.equal(r.takeover, null)
  assert.equal(r.kill, null)
  assert.equal(r.cannotStop, null)
})

test('three roots, a later one stolen: the owner rotates it out, and no thief move undoes that', () => {
  const r = run([['a', 'b', 'c']], ['a', 'b', 'c'], ['c'])
  assert.equal(r.takeover, null)
  assert.equal(r.kill, null)
  assert.equal(r.unrecoverable, null)
})

for (const [name, epochs, roots] of [
  ['two roots', [['a', 'b']], ['a', 'b']],
  ['three roots', [['a', 'b', 'c']], ['a', 'b', 'c']],
  ['three roots, the first already retired', [['a', 'b', 'c'], ['b', 'c', 'd']], ['a', 'b', 'c', 'd']],
]) {
  test(`${name}, the first root stolen: one record ends the identity (R3 at epoch 1)`, () => {
    const r = run(epochs, roots, ['a'])
    assert.deepEqual(evaluate('a', r.kill), { dead: true, at: 1 })
    assert.equal(r.takeover, null)
    assert.ok(r.unrecoverable)
  })
}

test('three roots, two stolen: the thief takes over; the owner can still end the identity', () => {
  const r = run([['a', 'b', 'c']], ['a', 'b', 'c'], ['b', 'c'])
  assert.ok(r.takeover)
  assert.equal(r.cannotStop, null)
})

test('a freeze never makes an inactive identity active', () => {
  for (const [epochs, roots, stolen] of [[[], ['a'], ['a']], [[['a', 'b']], ['a', 'b'], ['b']], [[['a', 'b', 'c']], ['a', 'b', 'c'], ['c']]]) {
    assert.equal(run(epochs, roots, stolen).freezeRevives, null)
  }
})

test('any past majority, even one fully retired, ends the identity with one record (R3 at that epoch)', () => {
  // Epoch 2 is {a, b, c}; epoch 3 retires b and c. b and c are still a majority of epoch 2.
  const r = run([['a', 'b', 'c'], ['a', 'd', 'e']], ['a', 'b', 'c', 'd', 'e'], ['b', 'c'])
  assert.deepEqual(evaluate('a', r.kill), { dead: true, at: 2 })
  assert.equal(r.takeover, null)
})

// Variant: membership records count only once a witness anchors the first valid record it sees for each epoch.
const runAnchored = (epochs, roots, stolen) => analyse({ genesis: 'a', history: history('a', epochs),
  owner: new Set([...roots, 'o']), thief: new Set([...stolen, 't']), universe: [...roots, 'o', 't'],
  maxEpoch: epochs.length + 3, thiefDepth: 1, anchored: true })

test('anchored: a stolen first or retired root can no longer end the identity', () => {
  for (const [epochs, roots] of [[[['a', 'b']], ['a', 'b']], [[['a', 'b', 'c']], ['a', 'b', 'c']],
    [[['a', 'b', 'c'], ['b', 'c', 'd']], ['a', 'b', 'c', 'd']]]) {
    const r = runAnchored(epochs, roots, ['a'])
    assert.equal(r.kill, null)
    assert.equal(r.takeover, null)
    assert.equal(r.unrecoverable, null)
  }
})

test('anchored: when the thief holds every root the owner holds, its takeover is final and the owner cannot end it', () => {
  for (const [epochs, roots, stolen] of [[[], ['a'], ['a']], [[['a', 'b', 'c']], ['a', 'b', 'c'], ['b', 'c']]]) {
    const r = runAnchored(epochs, roots, stolen)
    assert.ok(r.takeover)
    assert.ok(r.cannotStop)
  }
})

test('anchored: a later root stolen from two or three behaves as without anchoring', () => {
  assert.equal(runAnchored([['a', 'b']], ['a', 'b'], ['b']).cannotStop, null)
  const r = runAnchored([['a', 'b', 'c']], ['a', 'b', 'c'], ['c'])
  assert.equal(r.unrecoverable, null)
  assert.equal(r.kill, null)
})
