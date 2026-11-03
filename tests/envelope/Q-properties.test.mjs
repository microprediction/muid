// Q1–Q5 (TESTING.md §3.3) over generated bodies and signatures.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { env, envelopeText, oracleId, deepFrozen, TYPES } from './helpers.mjs'
import { record as inDomainObject } from '../encoding/arbitraries.mjs'
import { encoding } from '../impl.mjs'

const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 300)
const signed = fc.constantFrom(...TYPES.filter((t) => t !== 'root'))
const sig = inDomainObject.map((o) => encoding.encode(o)) // canonical sig text

test('Q1: changing only sig never changes the id', () => {
  fc.assert(fc.property(signed, inDomainObject, sig, sig, (type, body, s1, s2) => {
    const { payload, id } = env.seal(type, body)
    assert.equal(env.open(envelopeText(payload, s1), type).id, id)
    assert.equal(env.open(envelopeText(payload, s2), type).id, id)
  }), { seed: SEED, numRuns: RUNS })
})

test('Q2: seal, wrap and open round-trip; the id matches an independent SHA-256', () => {
  fc.assert(fc.property(fc.constantFrom(...TYPES), inDomainObject, (type, body) => {
    const sealed = env.seal(type, body)
    assert.equal(sealed.id, oracleId(sealed.payload))
    const text = env.wrap(sealed.payload, type === 'root' ? undefined : {})
    const r = env.open(text, type)
    assert.equal(r.id, sealed.id)
    assert.equal(r.payload, sealed.payload)
    assert.deepEqual(JSON.parse(JSON.stringify(r.body)), JSON.parse(JSON.stringify(body)))
  }), { seed: SEED, numRuns: RUNS })
})

test('Q3: any single-byte change to the payload is refused or changes the id', () => {
  let opened = 0
  fc.assert(fc.property(signed, inDomainObject, fc.nat(), fc.integer({ min: 32, max: 126 }), (type, body, at, code) => {
    const { payload, id } = env.seal(type, body)
    const i = at % payload.length
    const changed = payload.slice(0, i) + String.fromCharCode(code) + payload.slice(i + 1)
    fc.pre(changed !== payload)
    let r
    try { r = env.open(envelopeText(changed, '{}'), type) } catch (e) {
      assert.ok(env.EnvelopeError.isRefusal(e), String(e))
      return
    }
    opened++
    assert.notEqual(r.id, id)
  }), { seed: SEED, numRuns: RUNS })
  assert.ok(opened > 0, 'some mutations still open, so the id comparison ran')
})

test('Q4: refusal is total — arbitrary text either opens or throws EnvelopeError', () => {
  fc.assert(fc.property(fc.oneof(fc.string(), fc.json(), signed.chain((t) => inDomainObject.map((b) => envelopeText(env.seal(t, b).payload, '{}').replace(/1}"/, '2}"')))), (text) => {
    try { env.open(text, 'delegation') } catch (e) { assert.ok(env.EnvelopeError.isRefusal(e), String(e)) }
  }), { seed: SEED, numRuns: RUNS })
})

test('Q5: output is frozen with null prototypes, all the way down', () => {
  fc.assert(fc.property(signed, inDomainObject, (type, body) => {
    const r = env.open(envelopeText(env.seal(type, body).payload, '{"a":[{"b":1}]}'), type)
    assert.ok(deepFrozen(r))
    assert.equal(Object.getPrototypeOf(r), null)
    assert.equal(Object.getPrototypeOf(r.body), null)
    assert.equal(Object.getPrototypeOf(r.sig), null)
    assert.ok(Object.isFrozen(env.seal(type, body)))
  }), { seed: SEED, numRuns: RUNS })
})
