// The accept path: a well-formed assertion over the record, alone or with others; browser shapes.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { make, result, clientData, challengeFor, authData, RECORD, FLAGS, checkRootAssertion, CTX } from './helpers.mjs'

const OTHERS = ['0'.repeat(64), 'f'.repeat(64)]

test('a single-record assertion is accepted', () => assert.deepEqual(result(make()), { ok: true }))

test('the record covered together with up to seven others is accepted', () => {
  const covers = [...OTHERS.slice(0, 1), RECORD, ...Array.from({ length: 6 }, (_, i) => 'b' + String(i).repeat(63))].sort()
  assert.equal(covers.length, 8)
  assert.deepEqual(result(make({ covers })), { ok: true })
})

test("Chromium's extra client-data key is accepted", () => {
  const covers = [RECORD]
  const tail = ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"'
  assert.deepEqual(result(make({ cdj: clientData({ challenge: challengeFor(covers), tail }) })), { ok: true })
})

test('flag combinations a passkey produces are accepted: UP|UV, with BE, with BE|BS', () => {
  for (const flags of [FLAGS.UP | FLAGS.UV, FLAGS.UP | FLAGS.UV | FLAGS.BE, FLAGS.UP | FLAGS.UV | FLAGS.BE | FLAGS.BS]) {
    assert.deepEqual(result(make({ ad: authData({ flags }) })), { ok: true }, flags.toString(16))
  }
})

test('the signature counter is not consulted (W5)', () => {
  for (const count of [0, 1, 0xffffffff]) assert.deepEqual(result(make({ ad: authData({ count }) })), { ok: true })
})

test('results are frozen, with exactly { ok } or { ok, reason }', () => {
  const yes = checkRootAssertion(make(), CTX)
  const no = checkRootAssertion({}, CTX)
  assert.ok(Object.isFrozen(yes) && Object.isFrozen(no))
  assert.deepEqual(Object.keys(yes), ['ok'])
  assert.deepEqual(Object.keys(no), ['ok', 'reason'])
})
