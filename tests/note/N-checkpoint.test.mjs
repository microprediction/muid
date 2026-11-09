// C2SP tlog-checkpoint with Ed25519 log signatures and timestamped Ed25519 cosignatures (tlog-cosignature): form,
// origin, signatures, the cosigner quorum and its times.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { note } from '../impl.mjs'
import { keyPair, logLine, cosignLine, checkpointText, keyId, ORIGIN, ROOT, b64 } from './helpers.mjs'

const { verifyCheckpoint } = note
const NOW = 1_800_000_000
const LOG = keyPair(ORIGIN, 1, 1)
const C = [keyPair('witness.example/a', 4, 2), keyPair('witness.example/b', 4, 3), keyPair('witness.example/c', 4, 4)]
const CTX = Object.freeze({ origin: ORIGIN, log: LOG.vkey, cosigners: C.map((k) => k.vkey), quorum: 2, now: NOW, skew: 60 })
const plain = (r) => JSON.parse(JSON.stringify(r))
const refused = (reason) => ({ ok: false, reason })

function signed (text = checkpointText(), times = [NOW - 10, NOW - 20, NOW - 30], log = true) {
  return text + '\n' + (log ? logLine(LOG, text) : '') + C.map((k, i) => (times[i] === undefined ? '' : cosignLine(k, text, times[i]))).join('')
}

test('a checkpoint with the log signature and a quorum of cosignatures is accepted, with the cosigned times', () => {
  assert.deepEqual(plain(verifyCheckpoint(signed(), CTX)), { ok: true, origin: ORIGIN, size: 42, root: ROOT.toString('hex'), times: [NOW - 30, NOW - 20, NOW - 10] })
  assert.deepEqual(plain(verifyCheckpoint(signed(checkpointText(0)), CTX)).size, 0, 'size 0')
})

test('signature lines in any order, and unknown keys among them, are fine', () => {
  const text = checkpointText()
  const stranger = keyPair('witness.example/z', 4, 9)
  const lines = [cosignLine(C[1], text, NOW), cosignLine(stranger, text, NOW), logLine(LOG, text), cosignLine(C[0], text, NOW - 5)]
  assert.equal(verifyCheckpoint(text + '\n' + lines.join(''), CTX).ok, true)
  const sameName = keyPair('witness.example/a', 4, 7) // shares a name with a known key, not its ID
  assert.equal(verifyCheckpoint(text + '\n' + lines.join('') + cosignLine(sameName, text, NOW), CTX).ok, true)
})

test('the quorum: cosignatures counted only from distinct configured cosigners, not from the future', () => {
  assert.deepEqual(plain(verifyCheckpoint(signed(undefined, [NOW]), CTX)), refused('cosigners'), 'one of two')
  assert.equal(verifyCheckpoint(signed(undefined, [NOW, NOW + 60]), CTX).ok, true, 'skew allowed')
  assert.deepEqual(plain(verifyCheckpoint(signed(undefined, [NOW, NOW + 61]), CTX)), refused('cosigners'), 'one in the future')
  assert.deepEqual(plain(verifyCheckpoint(signed(undefined, [NOW, 2 ** 53 - 1]), CTX)), refused('cosigners'), 'a time far in the future')
  assert.deepEqual(plain(verifyCheckpoint(signed(undefined, [NOW, 2 ** 53]), CTX)), refused('signature'), 'a time this verifier cannot represent')
  assert.equal(verifyCheckpoint(signed(undefined, []), { ...CTX, quorum: 0 }).ok, true, 'quorum 0: the log alone')
  assert.deepEqual(plain(verifyCheckpoint(signed(undefined, [10, 9]), CTX)).times, [9, 10], 'times sorted as numbers, not as text')
})

test('the log signature is required, and every known signature must verify', () => {
  assert.deepEqual(plain(verifyCheckpoint(signed(undefined, undefined, false), CTX)), refused('log-signature'))
  const text = checkpointText()
  const other = checkpointText(43)
  assert.deepEqual(plain(verifyCheckpoint(text + '\n' + logLine(LOG, other) + cosignLine(C[0], text, NOW) + cosignLine(C[1], text, NOW), CTX)), refused('signature'), 'log signature over another text')
  assert.deepEqual(plain(verifyCheckpoint(text + '\n' + logLine(LOG, text) + cosignLine(C[0], other, NOW) + cosignLine(C[1], text, NOW), CTX)), refused('signature'), 'a cosignature over another text')
  const cosignedTime = cosignLine(C[0], text, NOW).replace(/ (\S+)\n$/, (_, s) => { const b = Buffer.from(s, 'base64'); b[11] ^= 1; return ' ' + b64(b) + '\n' })
  assert.deepEqual(plain(verifyCheckpoint(text + '\n' + logLine(LOG, text) + cosignedTime + cosignLine(C[1], text, NOW), CTX)), refused('signature'), 'a changed time')
  const asLog = `— ${C[0].name} ` + logLine(C[0], text).split(' ')[2] // a cosigner's key ID with a log-type signature: unknown
  assert.deepEqual(plain(verifyCheckpoint(text + '\n' + logLine(LOG, text) + asLog + cosignLine(C[1], text, NOW), CTX)), refused('cosigners'))
})

test('a repeated line from one known key is refused, before any signature is checked', () => {
  const text = checkpointText()
  const line = cosignLine(C[0], text, NOW)
  assert.deepEqual(plain(verifyCheckpoint(text + '\n' + logLine(LOG, text) + line + line + cosignLine(C[1], text, NOW), CTX)), refused('duplicate-signature'))
  const bad = logLine(LOG, checkpointText(43))
  assert.deepEqual(plain(verifyCheckpoint(text + '\n' + bad + bad, CTX)), refused('duplicate-signature'))
})

test('the origin must be the configured one', () => {
  const text = checkpointText(42, ROOT, 'log.example/other')
  assert.deepEqual(plain(verifyCheckpoint(signed(text), CTX)), refused('origin'))
})

test('checkpoint form: three lines, a canonical decimal size, a canonical base64 32-byte root, no extensions', () => {
  const root = b64(ROOT)
  for (const [name, text] of [
    ['two lines', `${ORIGIN}\n42\n`], ['an extension line', `${ORIGIN}\n42\n${root}\nextension\n`], ['an empty line', `${ORIGIN}\n\n42\n${root}\n`],
    ['size 042', `${ORIGIN}\n042\n${root}\n`], ['size +42', `${ORIGIN}\n+42\n${root}\n`], ['size 4.2e1', `${ORIGIN}\n4.2e1\n${root}\n`],
    ['size 2^53', `${ORIGIN}\n9007199254740992\n${root}\n`], ['size empty', `${ORIGIN}\n\n${root}\n`],
    ['a 31-byte root', `${ORIGIN}\n42\n${b64(ROOT.subarray(1))}\n`], ['a root without padding', `${ORIGIN}\n42\n${root.replace('=', '')}\n`],
    ['a root in base64url', `${ORIGIN}\n42\n${root.replace(/\+/g, '-').replace(/\//g, '_')}\n`],
    ['a root with non-zero padding bits', `${ORIGIN}\n42\n${root.slice(0, 42)}${String.fromCharCode(root.charCodeAt(42) + 1)}=\n`],
  ]) {
    assert.deepEqual(plain(verifyCheckpoint(signed(text), CTX)), refused('checkpoint-form'), name)
  }
  assert.equal(verifyCheckpoint(signed(`${ORIGIN}\n9007199254740991\n${root}\n`), CTX).ok, true, 'size 2^53 - 1')
})

test('note form: the signature block, its lines, and the characters allowed', () => {
  const text = checkpointText()
  const good = signed()
  for (const [name, n] of [
    ['no blank line', good.replace('\n\n', '\n')], ['no signatures', text + '\n'], ['no final newline', good.slice(0, -1)],
    ['a control character', good.replace(ORIGIN, ORIGIN + '\t')], ['a carriage return', good.replace(/\n— /, '\r\n— ')],
    ['a hyphen for the em dash', good.replace('— ', '- ')], ['two spaces', good.replace('— ', '—  ')],
    ['an empty signature', `${text}\n— ${ORIGIN} \n`], ['a short signature', `${text}\n— ${ORIGIN} AAAA\n`],
    ['a name with a plus', good.replace(`— ${ORIGIN}`, `— ${ORIGIN}+x`)], ['a lone surrogate', good.replace(ORIGIN, ORIGIN + '\ud800')],
    ['sixty-five signatures', text + '\n' + cosignLine(keyPair('x.example', 4, 5), text, NOW).repeat(65)],
    ['not a string', Buffer.from(good)], ['a String object', new String(good)], ['too long', good + 'x'.repeat(65536)], // eslint-disable-line no-new-wrappers
    ['text running into the signatures', '\n' + logLine(LOG, '')], ['garbage before a line', good.replace(/\n— /, '\nx— ')],
    ['garbage after a line', good.replace(/(\n— [^\n]*)\n/, '$1 x\n')], ['a four-byte signature', `${text}\n— ${ORIGIN} AAAAAA==\n` + logLine(LOG, text)],
  ]) {
    assert.deepEqual(plain(verifyCheckpoint(n, CTX)), refused('note-form'), name)
  }
  const many = text + '\n' + logLine(LOG, text) + cosignLine(C[0], text, NOW) + cosignLine(C[1], text, NOW) +
    Array.from({ length: 61 }, (_, i) => cosignLine(keyPair(`x.example/${i}`, 4, 10 + i), text, NOW)).join('')
  assert.equal(verifyCheckpoint(many, CTX).ok, true, 'sixty-four signatures, sixty-one of them unknown')
  assert.equal(verifyCheckpoint(good + `— ${'n'.repeat(255)} AAAAAAA=\n`, CTX).ok, true, 'an unknown five-byte signature under a 255-byte name')
  // C2SP signed-note: "Verifiers MUST ignore signatures from unknown keys", and puts no limit on a key name's length;
  // the 255-byte limit is tlog-cosignature's, on a cosigner's own name, so it holds for configured keys only (found by
  // review).
  assert.equal(verifyCheckpoint(good + `— ${'n'.repeat(256)} AAAAAAA=\n`, CTX).ok, true, 'an unknown signature under a 256-byte name')
  assert.equal(verifyCheckpoint(good + `— ${'n'.repeat(5000)} AAAAAAA=\n`, CTX).ok, true, 'and under a 5,000-byte name')
  assert.equal(note.verifyNote('\n\n' + logLine(LOG, '\n'), { keys: [LOG.vkey] }).ok, true, 'a text that is one empty line')
})

test('the size limit: a note of exactly 65,536 characters is read, one longer is not', () => {
  const sized = (n) => {
    const base = signed(checkpointText(42, ROOT, 'o'))
    const origin = 'o'.repeat(1 + n - base.length)
    const text = checkpointText(42, ROOT, origin)
    return { note: text + '\n' + logLine(LOG, text) + C.map((k) => cosignLine(k, text, NOW)).join(''), origin }
  }
  const at = sized(65536)
  assert.equal(at.note.length, 65536)
  assert.equal(verifyCheckpoint(at.note, { ...CTX, origin: at.origin }).ok, true)
  const over = sized(65537)
  assert.deepEqual(plain(verifyCheckpoint(over.note, { ...CTX, origin: over.origin })), refused('note-form'))
})

test('an empty origin line is a malformed checkpoint, not another origin', () => {
  assert.deepEqual(plain(verifyCheckpoint(signed(`\n42\n${b64(ROOT)}\n`), CTX)), refused('checkpoint-form'))
})

test('configuration errors are programming errors, each with its own message', () => {
  const n = signed()
  for (const [name, over, message] of [
    ['an empty origin', { origin: '' }, /log origin/], ['an origin that is not a string', { origin: 5 }, /log origin/],
    ['a cosigner key as the log key', { log: C[0].vkey }, /verifier key of type 1/], ['no log key', { log: undefined }, /verifier key of type 1/],
    ['a log key as a cosigner', { cosigners: [LOG.vkey] }, /verifier key of type 4/], ['a repeated cosigner', { cosigners: [C[0].vkey, C[0].vkey] }, /listed twice/],
    ['cosigners not a list', { cosigners: C[0].vkey }, /list of verifier keys/], ['quorum above the cosigners', { quorum: 4 }, /quorum/],
    ['negative quorum', { quorum: -1 }, /quorum/], ['quorum 1.5', { quorum: 1.5 }, /quorum/], ['no now', { now: undefined }, /now and skew/],
    ['negative now', { now: -1 }, /now and skew/], ['negative skew', { skew: -1 }, /now and skew/], ['skew 0.5', { skew: 0.5 }, /now and skew/],
  ]) {
    assert.throws(() => verifyCheckpoint(n, { ...CTX, ...over }), (e) => e instanceof TypeError && message.test(e.message), name)
  }
  for (const ctx of [null, undefined, 'x']) assert.throws(() => verifyCheckpoint(n, ctx), /context must be an object/)
  for (const ctx of [null, undefined, {}, { keys: 'x' }]) assert.throws(() => note.verifyNote(n, ctx), /list of verifier keys/)
  assert.equal(verifyCheckpoint(signed(undefined, [0, 0]), { ...CTX, now: 0, skew: 0 }).ok, true, 'now 0 and skew 0 are allowed')
})

test('two cosigners may share a name, with different keys; each counts once', () => {
  const twin = keyPair(C[0].name, 4, 8)
  const ctx = { ...CTX, cosigners: [C[0].vkey, twin.vkey], quorum: 2 }
  const text = checkpointText()
  assert.equal(verifyCheckpoint(text + '\n' + logLine(LOG, text) + cosignLine(C[0], text, NOW) + cosignLine(twin, text, NOW), ctx).ok, true)
  assert.deepEqual(plain(verifyCheckpoint(text + '\n' + logLine(LOG, text) + cosignLine(C[0], text, NOW), ctx)), refused('cosigners'))
})

// Verifier keys whose ID is computed correctly from their parts, so that only the named rule rejects each.
test('verifier keys: name rules, key length and type byte are checked, not just the key ID', () => {
  const pub = keyPair('x', 1, 1).pub
  const make = (name, type, material) => `${name}+${keyId(name, type, material).toString('hex')}+${b64(Buffer.concat([Buffer.from([type]), material]))}`
  const asKeys = (k) => () => note.verifyNote('x\n\n— a AAAAAAA=\n', { keys: [k] })
  for (const [label, k] of [['a space in the name', make('a b', 1, pub)], ['a 33-byte key', make('x', 1, Buffer.concat([pub, Buffer.from([0])]))],
    ['a 31-byte key', make('x', 1, pub.subarray(1))], ['a 256-byte name', make('n'.repeat(256), 1, pub)], ['an empty name', make('', 1, pub)],
    ['type byte 4 under a type 1 ID', `x+${keyId('x', 1, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([4]), pub]))}`]]) {
    assert.throws(asKeys(k), /not a verifier key/, label)
  }
  assert.equal(note.verifyNote('x\n\n— a AAAAAAA=\n', { keys: [make('n'.repeat(255), 1, pub)] }).reason, 'unverified', 'a 255-byte name is a name')
})

// Found by review: the Ed25519 cosignature message does not commit to the cosigner's name (C2SP tlog-cosignature), so
// one key under two names would let one cosignature count twice.
test('one public key configured as two cosigners is a programming error', () => {
  const same = keyPair('witness.example/again', 4, 2) // the seed of C[0]: the same key, another name
  assert.equal(Buffer.from(same.pub).equals(Buffer.from(C[0].pub)), true)
  assert.throws(() => verifyCheckpoint(signed(), { ...CTX, cosigners: [C[0].vkey, same.vkey] }), /listed twice/)
})

// Found by review: key names exclude Unicode White_Space (as Go's unicode.IsSpace), not JavaScript's \s.
test('key names: U+0085 is a space and is refused; U+FEFF is not a space and is allowed', () => {
  const pub = keyPair('x', 1, 1).pub
  const make = (name) => `${name}+${keyId(name, 1, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([1]), pub]))}`
  assert.throws(() => note.verifyNote('x\n\n— a AAAAAAA=\n', { keys: [make('bad\u0085name')] }), /not a verifier key/)
  assert.throws(() => note.verifyNote('x\n\n— a AAAAAAA=\n', { keys: [make('a\u3000b')] }), /not a verifier key/)
  assert.equal(note.verifyNote('x\n\n— a AAAAAAA=\n', { keys: [make('ok\ufeffname')] }).reason, 'unverified')
  assert.deepEqual(plain(verifyCheckpoint(signed() + '— bad\u0085name AAAAAAA=\n', CTX)), refused('note-form'), 'nor in a signature line')
})

// Two different keys whose 32-bit key IDs collide under one name (found by a birthday search over SHA-256 seeds): a
// signature line could belong to either, so the configuration is ambiguous, as in Go's VerifierList.
test('two different keys with the same name and key ID are a programming error', () => {
  const name = 'witness.example/collide'
  const vkey = (i) => {
    const pub = ed25519.getPublicKey(createHash('sha256').update('collide ' + i).digest())
    return `${name}+${keyId(name, 4, pub).toString('hex')}+${b64(Buffer.concat([Buffer.from([4]), pub]))}`
  }
  const [a, b] = [vkey(12946), vkey(59819)]
  assert.equal(a.split('+')[1], 'b40db076')
  assert.equal(b.split('+')[1], 'b40db076')
  assert.notEqual(a, b)
  assert.throws(() => verifyCheckpoint(signed(), { ...CTX, cosigners: [a, b], quorum: 0 }), /listed twice/)
})

// Found by review: the log's own key as a cosigner would let the log alone meet the quorum, with any time it chose.
// C2SP signed-note: one public key should not serve two signature types.
test("the log's own public key as a cosigner is a programming error", () => {
  const asCosigner = keyPair(ORIGIN, 4, 1) // the seed of LOG: its key, as a type 0x04 cosigner
  assert.equal(Buffer.from(asCosigner.pub).equals(Buffer.from(LOG.pub)), true)
  assert.throws(() => verifyCheckpoint(signed(), { ...CTX, cosigners: [asCosigner.vkey, C[1].vkey] }), /listed twice/)
})

// Found by review: configuration lists had their length read on every step. Read once, and an array length.
test('verifier keys: the list\'s length read once, and an array length', () => {
  const n = checkpointText(1, ROOT)
  for (const length of [Infinity, -1, 1.5, 2 ** 32]) {
    assert.throws(() => note.verifyNote(n, { keys: new Proxy([], { get (t, k) { if (k === 'length') return length; throw new Error('read past') } }) }), /list of verifier keys/, String(length))
  }
  let lengths = 0
  const growing = new Proxy([], { get (t, k) { if (k === 'length' && ++lengths > 100) throw new Error('read for ever'); return k === 'length' ? lengths : LOG.vkey } })
  assert.doesNotThrow(() => note.verifyNote(n, { keys: growing }))
  assert.equal(lengths, 1)
})
