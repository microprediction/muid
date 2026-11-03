// RFC 8032 §7.1: the five Ed25519 vectors verify; one flipped bit anywhere is rejected for the reason K5 predicts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { accepts, checkEd25519, bytes, REASONS } from './helpers.mjs'

const text = readFileSync(new URL('../vectors/rfc8032/rfc8032.txt', import.meta.url), 'latin1')
const section = text.slice(text.indexOf('7.1.  Test Vectors for Ed25519'), text.indexOf('7.2.  Test Vectors for Ed25519ctx'))

function field (block, name, next) {
  const a = block.indexOf(name)
  const b = block.indexOf(next, a + name.length)
  return block.slice(a + name.length, b).split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/.test(l)).join('')
}

const cases = section.split('-----TEST ').slice(1).map((block) => ({
  name: block.split('\n')[0].trim(),
  key: field(block, 'PUBLIC KEY:', 'MESSAGE'),
  msg: field(block, 'MESSAGE (length', 'SIGNATURE:'),
  sig: field(block, 'SIGNATURE:', '-----'),
}))

test('all five §7.1 vectors are found and well formed', () => {
  assert.deepEqual(cases.map((c) => c.name), ['1', '2', '3', '1024', 'SHA(abc)'])
  for (const c of cases) {
    assert.equal(c.key.length, 64, c.name)
    assert.equal(c.sig.length, 128, c.name)
  }
  assert.equal(cases[0].msg, '')
  assert.equal(cases[3].msg.length, 2046)
})

for (const c of cases) {
  test(`TEST ${c.name} verifies`, () => accepts(c.sig, bytes(c.msg), c.key, c.name))

  test(`TEST ${c.name}: every single-bit change of the signature or message is rejected`, () => {
    const msg = bytes(c.msg)
    const sig = bytes(c.sig)
    for (let i = 0; i < sig.length * 8; i++) {
      const s = Uint8Array.from(sig)
      s[i >> 3] ^= 1 << (i & 7)
      const r = checkEd25519(Buffer.from(s).toString('hex'), msg, c.key)
      assert.equal(r.ok, false, `sig bit ${i}`)
      assert.ok(REASONS.slice(4).includes(r.reason), `sig bit ${i}: ${r.reason}`)
      if (i >= 256 && i < 504) assert.equal(r.reason, 'sig-invalid', `S bit ${i}`) // S stays below L
    }
    for (let i = 0; i < Math.min(msg.length * 8, 512); i++) {
      const m = Uint8Array.from(msg)
      m[i >> 3] ^= 1 << (i & 7)
      assert.deepEqual({ ...checkEd25519(c.sig, m, c.key) }, { ok: false, reason: 'sig-invalid' }, `msg bit ${i}`)
    }
  })

  test(`TEST ${c.name}: every single-bit change of the key is rejected`, () => {
    const key = bytes(c.key)
    for (let i = 0; i < 256; i++) {
      const k = Uint8Array.from(key)
      k[i >> 3] ^= 1 << (i & 7)
      const r = checkEd25519(c.sig, bytes(c.msg), Buffer.from(k).toString('hex'))
      assert.equal(r.ok, false, `key bit ${i}`)
    }
  })
}
