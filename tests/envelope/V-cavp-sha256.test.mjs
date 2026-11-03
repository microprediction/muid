// The SHA-256 the record id uses (@noble/hashes) against NIST CAVP: every short and long message, count asserted.
// This checks the dependency, not our code.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { sha256 } from '@noble/hashes/sha2.js'

const DIR = new URL('../vectors/cavp-sha256/', import.meta.url)

function cases (file) {
  const text = readFileSync(new URL(file, DIR), 'latin1')
  const out = []
  let len
  let msg
  for (const line of text.split(/\r?\n/)) {
    const m = /^(Len|Msg|MD) = ([0-9a-f]*)$/.exec(line)
    if (!m) continue
    if (m[1] === 'Len') len = Number(m[2])
    else if (m[1] === 'Msg') msg = m[2]
    else out.push({ len, msg: len === 0 ? '' : msg, md: m[2] })
  }
  return out
}

for (const [file, count] of [['SHA256ShortMsg.rsp', 65], ['SHA256LongMsg.rsp', 64]]) {
  test(`${file}: all ${count} cases`, () => {
    const all = cases(file)
    assert.equal(all.length, count)
    for (const { len, msg, md } of all) {
      const bytes = Buffer.from(msg, 'hex')
      assert.equal(bytes.length * 8, len, `length of a ${len}-bit message`)
      assert.equal(Buffer.from(sha256(bytes)).toString('hex'), md, `${len}-bit message`)
    }
  })
}
