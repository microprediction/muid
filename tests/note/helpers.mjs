// Signed notes and checkpoints built from the C2SP specifications' wording, independently of src/note.js.
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'

export const b64 = (b) => Buffer.from(b).toString('base64')
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest()

// key ID = SHA-256(key name || 0x0A || signature type || public key)[:4]
export const keyId = (name, type, pub) => sha(Buffer.from(name, 'utf8'), [0x0a, type], pub).subarray(0, 4)

export function keyPair (name, type, seedByte) {
  const secret = Uint8Array.from({ length: 32 }, (_, i) => (seedByte * 31 + i) & 0xff)
  const pub = ed25519.getPublicKey(secret)
  const vkey = `${name}+${keyId(name, type, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([type]), pub]))}`
  return { name, type, secret, pub, vkey }
}

// An Ed25519 log signature line over the note text.
export function logLine (k, text) {
  const sig = ed25519.sign(Buffer.from(text, 'utf8'), k.secret)
  return `— ${k.name} ${b64(Buffer.concat([keyId(k.name, 1, k.pub), sig]))}\n`
}

// A timestamped Ed25519 cosignature line: the signature is over "cosignature/v1\ntime <t>\n" and the checkpoint text.
export function cosignLine (k, text, time) {
  const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(time))
  const sig = ed25519.sign(Buffer.from(`cosignature/v1\ntime ${time}\n${text}`, 'utf8'), k.secret)
  return `— ${k.name} ${b64(Buffer.concat([keyId(k.name, 4, k.pub), t, sig]))}\n`
}

export const ORIGIN = 'log.example/muid'
export const ROOT = createHash('sha256').update('root').digest()
export const checkpointText = (size = 42, root = ROOT, origin = ORIGIN) => `${origin}\n${size}\n${b64(root)}\n`
