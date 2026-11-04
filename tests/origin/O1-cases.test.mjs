// O1: canonical https origins only, by a fixed grammar; Node's WHATWG URL parser agrees with every accept.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fc from 'fast-check'
import { origin } from '../impl.mjs'

const { isCanonicalOrigin } = origin
const SEED = Number(process.env.FC_SEED ?? 20261103)
const RUNS = Number(process.env.FC_RUNS ?? 300)
const urlAgrees = (x) => { try { return new URL(x).origin === x } catch { return false } }

const label63 = 'a' + 'b'.repeat(61) + 'c'
const host253 = [label63, label63, label63, 'd'.repeat(58) + '.ex'].join('.')

const ACCEPT = [
  'https://example.org', 'https://a.b', 'https://a.b.c.d.e.example', 'https://x-1.y2.example', 'https://123.example',
  'https://example.org:1', 'https://example.org:444', 'https://example.org:8443', 'https://example.org:65535',
  `https://${label63}.example`, `https://${host253}`, 'https://a.b0c',
  // Near the URL Standard's numeric last label: none of these is a number to it.
  'https://a.0xg', 'https://a.b0x1', 'https://a.0b1', 'https://a.0o1', 'https://0x1.example', 'https://a.x0',
]

const REFUSE = [
  'http://example.org', 'HTTPS://example.org', 'https://Example.org', 'https://example.ORG', 'https://example.org.',
  'https://example.org/', 'https://example.org/path', 'https://example.org?q', 'https://example.org#f',
  'https://user@example.org', 'https://user:pw@example.org', 'https://example.org:443', 'https://example.org:0',
  'https://example.org:65536', 'https://example.org:080', 'https://example.org:', 'https://localhost', 'https://.example.org',
  'https://example..org', `https://${label63}d.example`, `https://${host253}x`, 'https://-a.example', 'https://a-.example',
  'https://xn--bcher-kva.example', 'https://ab--cd.example', 'https://a.xn--p1ai', 'https://192.168.0.1', 'https://1.2.3.4',
  'https://[::1]', 'https://example.123', 'https://a.b.0', 'https://exa%6dple.org', 'https://exa mple.org', ' https://example.org', 'https://example.org ',
  'https://example.org\n', 'https://exam\tple.org', 'https://ex_ample.org', 'https://example.org:+80', 'https://example.org:8 0',
  'https:///example.org', 'https:example.org', 'https://', '', 'https://é.example', 'https://example.org\u0000',
  // A last label of 0x and hex digits is a number to the URL Standard, so the host is parsed as IPv4 (or is
  // invalid). Found by automated review.
  'https://0x7f.0x1', 'https://1.2.3.0x4', 'https://example.0x1', 'https://a.0x', 'https://x.0x0', 'https://a.0xff',
]

test('hand cases: each listed origin is accepted, and Node\'s URL parser agrees it is canonical', () => {
  assert.equal(host253.length, 253)
  for (const x of ACCEPT) {
    assert.equal(isCanonicalOrigin(x), true, x)
    assert.equal(urlAgrees(x), true, `oracle: ${x}`)
  }
})

test('hand cases: each listed string is refused', () => {
  for (const x of REFUSE) assert.equal(isCanonicalOrigin(x), false, JSON.stringify(x))
})

test('non-strings are refused, including values whose string form is an origin', () => {
  for (const x of [undefined, null, 1, {}, [], ['https://example.org'], { toString: () => 'https://example.org' },
    new String('https://example.org'), new URL('https://example.org')]) {
    assert.equal(isCanonicalOrigin(x), false, String(x))
  }
})

const lbl = fc.stringMatching(/^[a-z0-9](?:[a-z0-9-]{0,10}[a-z0-9])?$/).filter((l) => l.slice(2, 4) !== '--')
// The last label is kept only where the oracle accepts it, so the generator does not restate the rule under test.
const tld = lbl.filter((l) => urlAgrees(`https://a.${l}`))
const generated = fc.tuple(fc.array(lbl, { minLength: 1, maxLength: 4 }), tld, fc.option(fc.integer({ min: 1, max: 65535 }).filter((p) => p !== 443)))
  .map(([labels, last, port]) => `https://${[...labels, last].join('.')}${port === null ? '' : ':' + port}`)

test('generated origins in the grammar are accepted, and the oracle agrees', () => {
  fc.assert(fc.property(generated, (x) => {
    assert.equal(isCanonicalOrigin(x), true, x)
    assert.equal(urlAgrees(x), true, x)
  }), { seed: SEED, numRuns: RUNS })
})

test('any single-character change to an accepted origin is refused or still canonical for the oracle', () => {
  let refused = 0
  fc.assert(fc.property(generated, fc.nat(), fc.integer({ min: 0, max: 0x7f }), (x, at, code) => {
    const i = at % x.length
    const y = x.slice(0, i) + String.fromCharCode(code) + x.slice(i + 1)
    if (isCanonicalOrigin(y)) assert.equal(urlAgrees(y), true, JSON.stringify(y))
    else refused++
  }), { seed: SEED, numRuns: RUNS })
  assert.ok(refused > RUNS / 4, `refused ${refused}`)
})

// The URL Standard's "ends in a number" (https://url.spec.whatwg.org/#ends-in-a-number-checker), checked against
// Node's parser rather than restated: over every last label up to four characters from the digits, the hex letters,
// x and o, and every 0x label with up to four hex digits, this validator accepts exactly when the parser keeps the
// origin as written.
test('numeric-looking last labels: accepted exactly when the URL parser agrees', () => {
  const ALPHABET = '0123456789abcdefxo'
  const labels = ['0x']
  const grow = (prefix, n) => { if (n === 0) return; for (const c of ALPHABET) { labels.push(prefix + c); grow(prefix + c, n - 1) } }
  grow('', 4)
  const hexGrow = (prefix, n) => { if (n === 0) return; for (const c of '0123456789abcdef') { labels.push(prefix + c); hexGrow(prefix + c, n - 1) } }
  hexGrow('0x', 4)
  let accepted = 0
  for (const l of labels) {
    const x = `https://a.${l}`
    assert.equal(isCanonicalOrigin(x), urlAgrees(x), x)
    if (urlAgrees(x)) accepted++
  }
  assert.ok(labels.length > 100_000 && accepted > 50_000 && accepted < labels.length, `${accepted} of ${labels.length}`)
})
