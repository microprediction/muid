// E1: string escaping checked against upstream RFC 8785 output bytes (tests/vectors/jcs/SOURCE.md, "Derived string
// vectors"). The expected bytes are cut from upstream's canonical output; nothing here is produced by our encoder.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { encode } from './helpers.mjs'

const NAMES = ['arrays', 'french', 'structures', 'unicode', 'values', 'weird']
// Counted by hand from the upstream output files: 3 + 8 + 16 + 2 + 4 + 18.
const EXPECTED_TOKENS = { arrays: 3, french: 8, structures: 16, unicode: 2, values: 4, weird: 18 }

// Every JSON string token, as raw text including its quotes, in order of appearance.
function stringTokens (text) {
  const out = []
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== '"') continue
    let j = i + 1
    while (text[j] !== '"') {
      if (text[j] === '\\') j++
      j++
      if (j >= text.length) throw new Error('unterminated string in upstream output')
    }
    out.push(text.slice(i, j + 1))
    i = j
  }
  return out
}

let total = 0
for (const name of NAMES) {
  const output = readFileSync(new URL(`../vectors/jcs/output/${name}.json`, import.meta.url), 'utf8')
  const tokens = stringTokens(output)

  test(`${name}: token count`, () => {
    assert.equal(tokens.length, EXPECTED_TOKENS[name])
  })

  tokens.forEach((token, n) => {
    total++
    test(`${name} #${n}: ${JSON.stringify(token)}`, () => {
      assert.equal(encode({ s: JSON.parse(token) }), '{"s":' + token + '}')
    })
  })
}

test('derived string vectors: total', () => {
  assert.equal(total, 51)
})
