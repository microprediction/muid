// SPEC §1, §6 F1, §11, §12: constructs banned from the trusted core (src/), and the core's line budget.
// Comments and string literals are blanked before matching, so prose about a banned word is not a finding.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SRC = new URL('../../src/', import.meta.url).pathname
const LINE_BUDGET = 1800

function files (dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    return statSync(p).isDirectory() ? files(p) : (/\.m?js$/.test(name) ? [p] : [])
  })
}

// Replaces comments and the contents of string and template literals with spaces, keeping line structure, so the
// patterns below see only code. Deliberately simple: the core's style keeps regex literals free of quotes.
export function codeOnly (text) {
  let out = ''
  let i = 0
  while (i < text.length) {
    const c = text[i]; const n = text[i + 1]
    if (c === '/' && n === '/') { while (i < text.length && text[i] !== '\n') { out += ' '; i++ } continue }
    if (c === '/' && n === '*') { out += '  '; i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) { out += text[i] === '\n' ? '\n' : ' '; i++ } out += '  '; i += 2; continue }
    if (c === '"' || c === "'" || c === '`') {
      out += c; i++
      while (i < text.length && text[i] !== c) {
        if (text[i] === '\\') { out += '  '; i += 2; continue }
        out += text[i] === '\n' ? '\n' : ' '; i++
      }
      out += c; i++
      continue
    }
    out += c; i++
  }
  return out
}

const BANS = [
  ['async function or arrow', /\basync\b/],
  ['await', /\bawait\b/],
  ['promise chaining', /\.then\s*\(|\bPromise\b/],
  // Reading the clock is banned; a reference such as Date.prototype.getTime (a brand check) is not a read.
  ['wall clock', /\bDate\s*\.\s*now\b|\bnew\s+Date\b|(?<![.\w])Date\s*\(|\bperformance\s*\.\s*now\b/],
  ['non-cryptographic randomness', /\bMath\s*\.\s*random\b/],
  ['browser storage', /\b(?:indexedDB|localStorage|sessionStorage)\b/],
  ['network', /\b(?:fetch|XMLHttpRequest|WebSocket)\b/],
  ['dynamic code', /\beval\s*\(|\bnew\s+Function\b|\bFunction\s*\(/],
  ['dynamic import', /\bimport\s*\(/],
  ['timers', /\b(?:setTimeout|setInterval|setImmediate|queueMicrotask)\b/],
  ['process environment', /\bprocess\s*\.\s*env\b/],
]
// JSON.parse is allowed in exactly one file: the decoder.
const JSON_PARSE_ALLOWED = new Set(['encode.js'])
// The only imports the core may have: noble, node built-ins none, and the core's own relative modules.
const IMPORT = /^\s*import\b[^'"]*['"]([^'"]+)['"]/gm
const ALLOWED_IMPORT = /^(?:\.\/[a-z0-9-]+\.js|@noble\/(?:curves|hashes)\/[a-z0-9./-]+\.js)$/

test('the core contains no banned construct', () => {
  const findings = []
  const all = files(SRC)
  assert.ok(all.length >= 1, 'found the core')
  for (const p of all) {
    const code = codeOnly(readFileSync(p, 'utf8'))
    const name = relative(SRC, p)
    for (const [label, re] of BANS) if (re.test(code)) findings.push(`${name}: ${label}`)
    if (/\bJSON\s*\.\s*parse\b/.test(code) && !JSON_PARSE_ALLOWED.has(name)) findings.push(`${name}: JSON.parse outside the decoder`)
  }
  assert.deepEqual(findings, [])
})

test('the core imports only noble and its own modules', () => {
  const findings = []
  for (const p of files(SRC)) {
    const text = readFileSync(p, 'utf8')
    for (const [, spec] of text.matchAll(IMPORT)) if (!ALLOWED_IMPORT.test(spec)) findings.push(`${relative(SRC, p)}: ${spec}`)
    if (/\brequire\s*\(/.test(codeOnly(text))) findings.push(`${relative(SRC, p)}: require()`)
  }
  assert.deepEqual(findings, [])
})

test(`the core is within its ${LINE_BUDGET}-line budget`, () => {
  const total = files(SRC).reduce((n, p) => n + readFileSync(p, 'utf8').split('\n').length, 0)
  assert.ok(total <= LINE_BUDGET, `${total} lines`)
})

// Anti-vacuity: each rule fires on a sample of what it bans, and not on prose or strings mentioning it.
test('every ban fires on an example and ignores comments and strings', () => {
  const EXAMPLES = {
    'async function or arrow': 'const f = async () => 1',
    await: 'x = await y',
    'promise chaining': 'p.then(f)',
    'wall clock': 'const t = Date.now()',
    'non-cryptographic randomness': 'Math.random()',
    'browser storage': 'localStorage.getItem(k)',
    network: 'fetch(u)',
    'dynamic code': 'eval(s)',
    'dynamic import': 'import(m)',
    timers: 'setTimeout(f, 1)',
    'process environment': 'process.env.X',
  }
  assert.equal(Object.keys(EXAMPLES).length, BANS.length)
  for (const [label, re] of BANS) {
    assert.ok(re.test(codeOnly(EXAMPLES[label])), `${label} fires`)
    assert.ok(!re.test(codeOnly(`// ${EXAMPLES[label]}\n/* ${EXAMPLES[label]} */\nconst s = '${EXAMPLES[label].replace(/'/g, '')}'`)), `${label} ignores comments and strings`)
  }
  const clock = BANS.find(([label]) => label === 'wall clock')[1]
  for (const read of ['new Date()', 'Date(0)', 'performance.now()']) assert.ok(clock.test(read), read)
  for (const reference of ['Date.prototype.getTime', 'x.Date(1)', 'const isDate = 1']) assert.ok(!clock.test(reference), reference)
  assert.ok(ALLOWED_IMPORT.test('./encode.js') && ALLOWED_IMPORT.test('@noble/curves/ed25519.js'))
  for (const bad of ['node:fs', 'canonicalize', '../tests/x.js', '@noble/curves', 'https://x.example/a.js', './Encode.js']) {
    assert.ok(!ALLOWED_IMPORT.test(bad), bad)
  }
})
