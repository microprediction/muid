// A note comes from whoever presents it: any string is refused or accepted, never thrown on, and any one-character
// change to a cosigned checkpoint is refused.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { note } from '../impl.mjs'
import { keyPair, logLine, cosignLine, checkpointText, ORIGIN } from './helpers.mjs'
import { runs } from '../runs.mjs'

const { verifyCheckpoint, verifyNote } = note
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = runs(300)
const NOW = 1_800_000_000
const LOG = keyPair(ORIGIN, 1, 1)
const C = [keyPair('witness.example/a', 4, 2), keyPair('witness.example/b', 4, 3)]
const CTX = { origin: ORIGIN, log: LOG.vkey, cosigners: C.map((k) => k.vkey), quorum: 2, now: NOW, skew: 60 }
const TEXT = checkpointText()
const GOOD = TEXT + '\n' + logLine(LOG, TEXT) + cosignLine(C[0], TEXT, NOW) + cosignLine(C[1], TEXT, NOW)
const CHARS = ['\n', ' ', '—', '+', '/', '=', 'A', 'a', '0', '9', '\t', 'é', ' ']

test('any input is refused or accepted, never thrown on', () => {
  fc.assert(fc.property(fc.oneof(fc.anything(), fc.string(), fc.string({ unit: 'binary' })), (x) => {
    assert.equal(typeof verifyCheckpoint(x, CTX).ok, 'boolean')
    assert.equal(typeof verifyNote(x, { keys: [LOG.vkey] }).ok, 'boolean')
  }), { seed: SEED, numRuns: RUNS })
})

test('any one-character change to a cosigned checkpoint is refused', () => {
  assert.equal(verifyCheckpoint(GOOD, CTX).ok, true)
  fc.assert(fc.property(fc.nat(), fc.constantFrom('replace', 'insert', 'delete'), fc.constantFrom(...CHARS), (at, op, ch) => {
    const i = at % GOOD.length
    const changed = op === 'insert' ? GOOD.slice(0, i) + ch + GOOD.slice(i) : op === 'replace' ? GOOD.slice(0, i) + ch + GOOD.slice(i + 1) : GOOD.slice(0, i) + GOOD.slice(i + 1)
    if (changed === GOOD) return
    assert.equal(verifyCheckpoint(changed, CTX).ok, false, JSON.stringify(changed))
  }), { seed: SEED, numRuns: RUNS })
})
