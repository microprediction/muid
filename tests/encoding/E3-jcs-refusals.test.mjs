// E3 + E5: every upstream RFC 8785 input lies outside our value domain and is refused with one defined reason.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { encode, refuses } from './helpers.mjs'

// Reasons follow E5's visiting order: top level first, then keys in canonical order, key before value.
const CASES = {
  arrays: 'top-level', // the top level is an array
  french: 'key', // "péché" is the first key outside the grammar
  structures: 'key', // "" sorts first
  unicode: 'key', // "Unnormalized Unicode"
  values: 'null', // "literals" sorts first and holds null before true/false
  weird: 'key', // "\n" sorts first
}

test('upstream refusal count', () => {
  assert.equal(Object.keys(CASES).length, 6)
})

for (const [name, reason] of Object.entries(CASES)) {
  test(`${name}: refused with "${reason}"`, () => {
    const input = JSON.parse(readFileSync(new URL(`../vectors/jcs/input/${name}.json`, import.meta.url), 'utf8'))
    refuses(() => encode(input), reason, name)
  })
}
