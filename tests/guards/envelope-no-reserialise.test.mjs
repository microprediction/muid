// TESTING.md §3.4: open never re-serialises what it verifies. No vector can catch a decoder that hashes a
// re-encoding while E2 holds, so this checks the source: encode is used only in seal and wrap.
// (A source check: it lives with the guards, outside the mutation run, whose sandbox instruments src/.)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'

test('src/envelope.js calls encode only inside seal and wrap, so open never re-serialises what it verifies', () => {
  const path = new URL('../../src/envelope.js', import.meta.url)
  assert.ok(existsSync(path), 'src/envelope.js exists')
  let src = readFileSync(path, 'utf8').replace(/\/\/.*$/gm, '')
  for (const name of ['seal', 'wrap']) {
    const at = src.indexOf(`export function ${name} (`)
    assert.ok(at >= 0, `${name} is declared as \`export function ${name} (\``)
    const end = src.indexOf('\n}\n', at)
    assert.ok(end > at)
    src = src.slice(0, at) + src.slice(end)
  }
  const body = src.split('\n').filter((line) => !line.startsWith('import ')).join('\n')
  // A property access such as TextEncoder.prototype.encode is not the encoder.
  assert.deepEqual(body.match(/(?<![.\w$])encode\b/g) ?? [], [], 'encode appears only in imports and in seal and wrap')
})
