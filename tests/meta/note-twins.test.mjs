// SPEC §12 and TESTING.md §6: the signed-note and checkpoint suite must fail against every broken twin, and pass against the real module run
// through the same harness. Twins are generated from src/note.js by one targeted change each.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdtempSync, rmSync, readdirSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { tmpdir, availableParallelism } from 'node:os'
import { join } from 'node:path'

const SRC = new URL('../../src/note.js', import.meta.url)
const SUITE_DIR = new URL('../note/', import.meta.url).pathname
const SUITE = readdirSync(SUITE_DIR).filter((f) => f.endsWith('.test.mjs')).map((f) => join(SUITE_DIR, f))

// A twin lives outside the repository, so its imports are made absolute.
const IMPORTS = [
  ["from './bytes.js'", "from '" + new URL('../../src/bytes.js', import.meta.url).href + "'"],
  ["from '@noble/hashes/sha2.js'", "from '" + import.meta.resolve('@noble/hashes/sha2.js') + "'"],
  ["from './ed25519.js'", "from '" + new URL('../../src/ed25519.js', import.meta.url).href + "'"],
]

// [name, bug class, [find, replace] pairs]
const TWINS = [
  ['name-only-match', 'a signature line is matched to a key by name alone', [['if (p.lines[i].name === keys[k].name && p.lines[i].id === keys[k].id) {', 'if (p.lines[i].name === keys[k].name) {']]],
  ['non-canonical-base64', 'base64 with non-zero padding bits is accepted', [['  if (btoa(bin) !== s) return undefined\n', '']]],
  ['duplicates-accepted', 'a repeated line from one key is accepted', [["        if (at[k] >= 0) return 'duplicate-signature'\n", '']]],
  ['cosignature-without-time', 'a cosignature is checked over the text alone, so its time is unsigned', [["message = 'cosignature/v1\\ntime ' + time[k] + '\\n' + p.text", 'message = p.text']]],
  ['future-counted', 'cosignatures from the future count towards the quorum', [['if (s.time[k] <= c.now + c.skew)', 'if (s.time[k] >= 0)']]],
  ['quorum-unchecked', 'any number of cosignatures is enough', [["  if (times.length < c.quorum) return refuse('cosigners')\n", '']]],
  ['log-signature-optional', 'a checkpoint without the log signature is accepted', [["  if (s.at[0] < 0) return refuse('log-signature')\n", '']]],
  ['origin-unchecked', 'a checkpoint of another log is accepted', [["  if (lines[0] !== c.origin) return refuse('origin')\n", '']]],
  ['extensions-accepted', 'extension lines after the root are accepted', [["  if (lines.length !== 3) return refuse('checkpoint-form')", "  if (lines.length < 3) return refuse('checkpoint-form')"]]],
  ['first-blank-line', 'the text is split at the first blank line, not the last', [["apply(lastIndexOf, note, ['\\n\\n'])", "apply(indexOf, note, ['\\n\\n'])"]]],
  ['key-id-unchecked', 'a verifier key is accepted whatever its key ID', [['    keyId(name, type, key.subarray(1)) !== id) throw', '    false) throw']]],
  ['repeated-cosigner', 'a cosigner listed twice counts twice', [["throw new TypeError('a key is listed twice')", '{}']]],
  ['same-key-two-names', 'one key configured under two cosigner names counts twice', [[' || out[j].key === out[i].key', '']]],
  ['js-whitespace-names', "key names use JavaScript's \\s, which misses U+0085", [['const NAME = /^[^\\p{White_Space}+', 'const NAME = /^[^\\s+']]],
  ['leading-zeros', 'a size with leading zeros is accepted', [['const DECIMAL = /^(?:0|[1-9][0-9]*)$/', 'const DECIMAL = /^[0-9]+$/']]],
]

function run (implPath) {
  const { NODE_TEST_CONTEXT, ...env } = process.env
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', ...SUITE], {
      env: { ...env, MUID_NOTE_IMPL: implPath ?? '', FC_RUNS: '100' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', (code) => {
      const count = (k) => Number((out.match(new RegExp(`^# ${k} (\\d+)`, 'm')) ?? [])[1] ?? NaN)
      resolve({ code, pass: count('pass'), fail: count('fail') })
    })
  })
}

const source = readFileSync(SRC, 'utf8')
const dir = mkdtempSync(join(tmpdir(), 'muid-note-twins-'))

function generate (name, edits) {
  let text = source
  for (const [find, replace] of [...IMPORTS, ...edits]) {
    const n = text.split(find).length - 1
    assert.equal(n, 1, `twin ${name}: target must occur exactly once in src/note.js, found ${n}: ${JSON.stringify(find)}`)
    text = text.replace(find, () => replace)
  }
  const path = join(dir, `${name}.js`)
  writeFileSync(path, text)
  return path
}

test('note broken twins', { timeout: 600_000 }, async (t) => {
  try {
    await t.test('control: an unmodified copy, run from outside the repository, passes', async () => {
      const r = await run(generate('control', []))
      assert.equal(r.code, 0, `control: exit ${r.code}, ${r.fail} failing`)
      assert.ok(r.pass >= 9, `control: only ${r.pass} tests ran`)
    })

    const jobs = TWINS.map(([name, why, edits]) => [name, why, generate(name, edits)])
    assert.equal(jobs.length, 15, 'twin count')
    const results = []
    const queue = [...jobs]
    const workers = Math.max(1, Math.floor(availableParallelism() / 4))
    await Promise.all(Array.from({ length: workers }, async () => {
      for (let job = queue.shift(); job; job = queue.shift()) {
        const [name, why, path] = job
        results.push([name, why, await run(path)])
      }
    }))
    results.sort((a, b) => jobs.findIndex((j) => j[0] === a[0]) - jobs.findIndex((j) => j[0] === b[0]))
    for (const [name, why, r] of results) {
      await t.test(`twin ${name} is caught (${why})`, () => {
        assert.notEqual(r.code, 0, `the suite passed against twin ${name}`)
        assert.ok(r.pass > 0 && r.fail > 0, `twin ${name}: the suite did not run normally (pass ${r.pass}, fail ${r.fail})`)
      })
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
