// P3 (E2): after any one-character change to a valid encoding, decode either refuses it with an EncodingError or
// returns a value whose encoding is exactly the changed text.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fc, record } from './arbitraries.mjs'
import { encode, decode, EncodingError } from './helpers.mjs'

const CHARS = ['"', '\\', ',', ':', '{', '}', '[', ']', ' ', '\n', '0', '1', '9', '-', '.', 'e', 'E', 'a', 'z', 'u', 'n', 't']

test('canonical input', () => {
  let accepted = 0; let refused = 0
  fc.assert(fc.property(
    record, fc.nat(), fc.constantFrom('replace', 'insert', 'delete'), fc.constantFrom(...CHARS),
    (v, pos, op, ch) => {
      const b = encode(v)
      const i = pos % (b.length + 1)
      const mutated = op === 'insert' ? b.slice(0, i) + ch + b.slice(i)
        : op === 'replace' ? b.slice(0, i) + ch + b.slice(i + 1)
          : b.slice(0, i) + b.slice(i + 1)
      let out
      try {
        out = decode(mutated)
      } catch (e) {
        assert.ok(e instanceof EncodingError, `non-EncodingError for ${JSON.stringify(mutated)}: ${e}`)
        refused++
        return
      }
      accepted++
      assert.equal(encode(out), mutated)
    },
  ), { numRuns: Number(process.env.FC_RUNS ?? 2000) })
  // Anti-vacuity: both outcomes occur, so neither branch is untested.
  assert.ok(accepted > 0, `accepted mutants: ${accepted}`)
  assert.ok(refused > 0, `refused mutants: ${refused}`)
})
