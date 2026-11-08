// Tamper sweep: every one-character change to any record a claim rests on (the claim, its delegation, the root record
// and the head) is refused. Each position is replaced by two other characters and deleted; none may verify.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { v, RECORDS, CALL } from './records.mjs'

// Two replacements that differ from the original and from each other, so each position meets a character of another
// class as well as one of a nearby class: a hex digit becomes another hex digit, and so on.
function replacements (ch) {
  const near = String.fromCharCode(ch.charCodeAt(0) ^ 1)
  const far = ch === '0' ? '1' : '0'
  return near === far ? [near, 'x'] : [near, far]
}

function variants (text) {
  const out = []
  for (let i = 0; i < text.length; i++) {
    for (const r of replacements(text[i])) out.push(text.slice(0, i) + r + text.slice(i + 1))
    out.push(text.slice(0, i) + text.slice(i + 1))
  }
  return out
}

test('the untampered records verify', () => {
  assert.equal(v.verifyClaim(RECORDS, CALL).ok, true)
  assert.equal(v.verifyDelegation(RECORDS, CALL).ok, true)
})

for (const name of ['claim', 'delegation', 'root', 'head', 'logged']) {
  test(`every one-character change to the ${name} is refused`, () => {
    const all = variants(RECORDS[name])
    let accepted = 0
    const first = []
    for (const t of all) {
      const r = v.verifyClaim({ ...RECORDS, [name]: t }, CALL)
      if (r.ok) {
        accepted++
        if (first.length < 3) first.push(t)
      }
    }
    assert.equal(accepted, 0, `${accepted} of ${all.length} verified, e.g. ${first.join('\n')}`)
    assert.ok(all.length > 3 * 100, 'the sweep covers the whole record')
  })
}
