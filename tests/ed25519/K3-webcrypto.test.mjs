// K3: delegate keys are WebCrypto Ed25519 keys. What WebCrypto signs, checkEd25519 accepts; and where WebCrypto signs
// deterministically (Node, Chromium, Firefox), it produces noble's bytes for the same key and message.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { ed25519 } from '@noble/curves/ed25519.js'
import { checkEd25519, hex } from './helpers.mjs'
import { runs } from '../runs.mjs'

const { subtle } = globalThis.crypto
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = runs(50)

test('a non-extractable WebCrypto key signs what checkEd25519 accepts, and its secret cannot be exported', async () => {
  const { privateKey, publicKey } = await subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
  assert.equal(privateKey.extractable, false)
  await assert.rejects(subtle.exportKey('pkcs8', privateKey))
  const pub = hex(await subtle.exportKey('raw', publicKey))
  const msg = new TextEncoder().encode('muid/v1/accept\n' + 'x'.repeat(32))
  const sig = hex(await subtle.sign({ name: 'Ed25519' }, privateKey, msg))
  assert.deepEqual({ ...checkEd25519(sig, msg, pub) }, { ok: true })
})

test('for the same key and message, WebCrypto here signs exactly noble\'s bytes (a differential test)', async () => {
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex')
  await fc.assert(fc.asyncProperty(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ maxLength: 200 }), async (seed, msg) => {
    const key = await subtle.importKey('pkcs8', Buffer.concat([pkcs8Prefix, seed]), { name: 'Ed25519' }, false, ['sign'])
    const web = hex(await subtle.sign({ name: 'Ed25519' }, key, msg))
    assert.equal(web, hex(ed25519.sign(msg, seed)))
    assert.deepEqual({ ...checkEd25519(web, msg, hex(ed25519.getPublicKey(seed))) }, { ok: true })
  }), { seed: SEED, numRuns: RUNS })
})
