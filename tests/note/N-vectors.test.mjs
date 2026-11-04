// C2SP signed notes against the reference implementation's vectors (Go's sumdb/note) and a real checkpoint (the Go
// checksum database), and verifier keys from transparency-dev/formats.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { note } from '../impl.mjs'

const { verifyNote, verifyCheckpoint } = note
const V = (f) => readFileSync(new URL(`../vectors/c2sp-note/${f}`, import.meta.url), 'utf8')
const go = JSON.parse(V('go-note.json'))
const td = JSON.parse(V('tdev-cosignature.json'))
const plain = (r) => JSON.parse(JSON.stringify(r))

test('Go TestOpen: a known key verifies, an unknown one is ignored, no known key is refused', () => {
  const msg = go.text + '\n' + go.peterSig + go.enochSig
  assert.deepEqual(plain(verifyNote(msg, { keys: [go.vkeys.peter] })), { ok: true, text: go.text, signers: ['PeterNeumann'] })
  assert.deepEqual(plain(verifyNote(msg, { keys: [go.vkeys.peter, go.vkeys.enoch] })), { ok: true, text: go.text, signers: ['PeterNeumann', 'EnochRoot'] })
  assert.deepEqual(plain(verifyNote(msg, { keys: [] })), { ok: false, reason: 'unverified' })
  assert.deepEqual(plain(verifyNote(go.text + '\n' + go.peterSig, { keys: [go.vkeys.enoch] })), { ok: false, reason: 'unverified' })
})

test('Go TestOpen: more than the signature limit, and a changed signature, are refused', () => {
  assert.deepEqual(plain(verifyNote(go.text + '\n' + go.enochSig.repeat(101), { keys: [go.vkeys.peter] })), { ok: false, reason: 'note-form' })
  const changed = go.text + '\n' + go.peterSig.slice(0, 60) + 'ABCD' + go.peterSig.slice(60)
  assert.equal(verifyNote(changed, { keys: [go.vkeys.peter] }).ok, false)
})

// Known difference: Go ignores a repeated signature line from one key; a checkpoint must not carry one (C2SP
// tlog-checkpoint), and this verifier refuses it in any note.
test('a repeated signature line from a known key is refused (Go ignores it)', () => {
  assert.deepEqual(plain(verifyNote(go.text + '\n' + go.peterSig + go.peterSig, { keys: [go.vkeys.peter] })), { ok: false, reason: 'duplicate-signature' })
  assert.equal(verifyNote(go.text + '\n' + go.enochSig + go.enochSig + go.peterSig, { keys: [go.vkeys.peter] }).ok, true, 'unknown repeats are ignored')
})

test('Go TestNewVerifier and transparency-dev: malformed verifier keys are programming errors', () => {
  for (const k of [...go.badVkeys, ...td.badVkeys, 'PeterNeumann+C74F20A3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW']) {
    assert.throws(() => verifyNote(go.text + '\n' + go.peterSig, { keys: [k] }), /not a verifier key of type 1/, k)
  }
  assert.throws(() => verifyNote(go.text + '\n' + go.peterSig, { keys: [td.cosignerVkey] }), /not a verifier key of type 1/, 'a cosigner key is not a note key')
})

test('the Go checksum database checkpoint verifies under its published key', () => {
  const r = verifyCheckpoint(V('sumdb-checkpoint.txt'), { origin: 'go.sum database tree', log: V('sumdb-vkey.txt').trim(), cosigners: [], quorum: 0, now: 1_800_000_000, skew: 60 })
  assert.deepEqual(plain(r), { ok: true, origin: 'go.sum database tree', size: 70763141,
    root: Buffer.from('6Sqx+Iavkc4cOTVydAWzM8kNFTUrbtbU78pWA8i1CR0=', 'base64').toString('hex'), times: [] })
  const changed = V('sumdb-checkpoint.txt').replace('70763141', '70763142')
  assert.deepEqual(plain(verifyCheckpoint(changed, { origin: 'go.sum database tree', log: V('sumdb-vkey.txt').trim(), cosigners: [], quorum: 0, now: 1_800_000_000, skew: 60 })),
    { ok: false, reason: 'signature' })
})
