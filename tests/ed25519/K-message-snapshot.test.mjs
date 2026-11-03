// The message is copied once, before any check: a Uint8Array subclass cannot change what is verified while it is
// being verified. Found by adversarial review.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { ed25519 } from '@noble/curves/ed25519.js'
import { checkEd25519, hex, bytes } from './helpers.mjs'

const secret = bytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
const KEY = hex(ed25519.getPublicKey(secret))
const enc = (s) => new TextEncoder().encode(s)

test('a subclass whose length getter swaps its contents during verification is checked on its contents at entry', () => {
  const shown = enc('pay alice   10')
  const signed = enc('pay mallory 99')
  const sig = hex(ed25519.sign(signed, secret))
  class Swap extends Uint8Array {
    get length () { this.calls = (this.calls ?? 0) + 1; this.set(this.calls === 1 ? signed : shown); return super.length }
  }
  const m = new Swap(shown)
  assert.deepEqual({ ...checkEd25519(sig, m, KEY) }, { ok: false, reason: 'sig-invalid' })
  assert.deepEqual({ ...checkEd25519(sig, signed, KEY) }, { ok: true }, 'control')
})

test('a subclass that lies about its length is checked on its real bytes', () => {
  const m = enc('hello')
  const sig = hex(ed25519.sign(new Uint8Array([...m, 0, 0, 0]), secret))
  class Liar extends Uint8Array { get length () { return super.length + 3 } }
  assert.deepEqual({ ...checkEd25519(sig, new Liar(m), KEY) }, { ok: false, reason: 'sig-invalid' })
})

test('a Uint8Array subclass from another realm is checked on its bytes', () => {
  const m = enc('cross realm')
  const sig = hex(ed25519.sign(m, secret))
  const foreign = vm.runInNewContext('class Foo extends Uint8Array {}; new Foo(src)', { src: m })
  assert.deepEqual({ ...checkEd25519(sig, foreign, KEY) }, { ok: true })
})

test('a message whose buffer is detached is a programming error', () => {
  const m = new Uint8Array(4)
  structuredClone(m.buffer, { transfer: [m.buffer] })
  assert.throws(() => checkEd25519('00'.repeat(64), m, KEY), { name: 'TypeError', message: 'message must be a Uint8Array' })
})
