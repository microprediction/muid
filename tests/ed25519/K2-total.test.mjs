// K2, K5: for any sig and key value the result is a frozen { ok, reason? } with a K5 reason — never a throw. Hex must
// be exactly lowercase, of the exact length.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { checkEd25519, REASONS, rejects } from './helpers.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 300)
const KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a' // RFC 8032 TEST 1
const SIG = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'
const EMPTY = new Uint8Array(0)

function shaped (r) {
  assert.ok(Object.isFrozen(r))
  if (r.ok) assert.deepEqual(Object.keys(r), ['ok'])
  else {
    assert.deepEqual(Object.keys(r), ['ok', 'reason'])
    assert.ok(REASONS.includes(r.reason), r.reason)
  }
}

test('the RFC vector is the control', () => assert.deepEqual({ ...checkEd25519(SIG, EMPTY, KEY) }, { ok: true }))

test('arbitrary values as sig and key give a well-shaped result, never a throw', () => {
  const any = fc.oneof(fc.string(), fc.hexaString?.() ?? fc.string(), fc.anything(), fc.uint8Array(),
    fc.stringMatching(/^[0-9a-f]{64}$/), fc.stringMatching(/^[0-9a-f]{128}$/))
  fc.assert(fc.property(any, any, fc.uint8Array({ maxLength: 64 }), (sig, key, msg) => {
    shaped(checkEd25519(sig, msg, key))
  }), { seed: SEED, numRuns: RUNS })
})

test('random well-formed hex keys and signatures are rejected with a K5 reason, never a throw', () => {
  let keyStage = 0
  fc.assert(fc.property(fc.stringMatching(/^[0-9a-f]{128}$/), fc.stringMatching(/^[0-9a-f]{64}$/), (sig, key) => {
    const r = checkEd25519(sig, EMPTY, key)
    shaped(r)
    assert.equal(r.ok, false)
    if (r.reason.startsWith('key-')) keyStage++
  }), { seed: SEED, numRuns: RUNS })
  assert.ok(keyStage < RUNS, 'some random keys get past the key checks')
})

test('hex that is not exactly lowercase of the right length is an encoding refusal', () => {
  const bad = (h) => [h.toUpperCase(), h.slice(1), h + '0', h + '00', '0x' + h.slice(2), ' ' + h.slice(1), h.slice(0, -1) + 'g', '']
  for (const k of bad(KEY)) rejects(SIG, EMPTY, k, 'key-encoding', JSON.stringify(k))
  for (const s of bad(SIG)) rejects(s, EMPTY, KEY, 'sig-encoding', JSON.stringify(s))
  for (const v of [undefined, null, 1, {}, [], new Uint8Array(32)]) {
    rejects(SIG, EMPTY, v, 'key-encoding', String(v))
    rejects(v, EMPTY, KEY, 'sig-encoding', String(v))
  }
})

test('a message that is not a Uint8Array is a programming error', () => {
  for (const m of ['', [], null, undefined, Buffer.from('').buffer]) {
    assert.throws(() => checkEd25519(SIG, m, KEY), TypeError, String(m))
  }
})

test('key checks come before signature checks', () => {
  rejects('not hex', EMPTY, 'not hex', 'key-encoding', 'both bad')
  rejects('not hex', EMPTY, '0100000000000000000000000000000000000000000000000000000000000000', 'key-small-order', 'bad sig, small key')
})
