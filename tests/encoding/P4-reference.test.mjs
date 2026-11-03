// P4 (E1): on in-domain records the encoder agrees with an independent RFC 8785 implementation (canonicalize,
// pinned dev dependency). Shared limitation: both format strings with JSON.stringify, so string escaping is checked
// independently by E1-jcs-derived-strings instead.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import canonicalize from 'canonicalize'
import { fc, record } from './arbitraries.mjs'
import { encode } from './helpers.mjs'

test('agrees with the reference implementation', () => {
  let runs = 0; let multiKey = 0
  fc.assert(fc.property(record, (v) => {
    runs++
    if (Object.keys(v).length > 1) multiKey++
    assert.equal(encode(v), canonicalize(v))
  }))
  assert.ok(multiKey / runs >= 0.2, `inputs with several top-level keys: ${multiKey}/${runs}`)
})
