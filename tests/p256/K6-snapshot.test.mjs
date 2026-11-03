// Message and signature bytes are copied once, before any check: a Uint8Array subclass cannot change what is
// verified while it is being verified (as found for Ed25519 by adversarial review).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { checkP256, hex } from './helpers.mjs'

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const jwk = publicKey.export({ format: 'jwk' })
const KEY = '04' + hex(Buffer.from(jwk.x, 'base64url')) + hex(Buffer.from(jwk.y, 'base64url'))
const enc = (s) => new TextEncoder().encode(s)
const sign = (m) => new Uint8Array(nodeSign('sha256', m, { key: privateKey, dsaEncoding: 'der' }))

test('a message subclass that swaps its contents during verification is checked on its contents at entry', () => {
  const shown = enc('pay alice   10')
  const signed = enc('pay mallory 99')
  const sig = sign(signed)
  class Swap extends Uint8Array {
    get length () { this.calls = (this.calls ?? 0) + 1; this.set(this.calls === 1 ? signed : shown); return super.length }
  }
  assert.deepEqual({ ...checkP256(sig, new Swap(shown), KEY) }, { ok: false, reason: 'sig-invalid' })
  assert.deepEqual({ ...checkP256(sig, signed, KEY) }, { ok: true }, 'control')
})

test('a signature subclass that changes during verification is checked on its bytes at entry', () => {
  const m = enc('message')
  const good = sign(m)
  const bad = Uint8Array.from(good); bad[bad.length - 1] ^= 1
  class Swap extends Uint8Array {
    get length () { this.calls = (this.calls ?? 0) + 1; if (this.calls > 1) this.set(good); return super.length }
  }
  assert.equal(checkP256(new Swap(bad), m, KEY).ok, false)
})

test('Uint8Array subclasses from another realm are checked on their bytes', () => {
  const m = enc('cross realm')
  const sig = sign(m)
  const make = (src) => vm.runInNewContext('class Foo extends Uint8Array {}; new Foo(src)', { src })
  assert.deepEqual({ ...checkP256(make(sig), make(m), KEY) }, { ok: true })
})

test('a detached message is a programming error; a detached signature is sig-encoding', () => {
  const detach = (u) => { structuredClone(u.buffer, { transfer: [u.buffer] }); return u }
  assert.throws(() => checkP256(sign(enc('x')), detach(new Uint8Array(4)), KEY), { name: 'TypeError' })
  assert.deepEqual({ ...checkP256(detach(sign(enc('x'))), enc('x'), KEY) }, { ok: false, reason: 'sig-encoding' })
})
