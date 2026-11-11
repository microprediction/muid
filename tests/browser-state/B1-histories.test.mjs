import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

// vm modules preserve the page's real ESM import and its own module lexical
// state per document. The VM flag is confined to this child, not required by the
// production app or the rest of the test suite.
test('id page histories preserve authorization, persistence and cancellation', { timeout: 300_000 }, async () => {
  const child = spawn(process.execPath, ['--experimental-vm-modules', fileURLToPath(new URL('./run.mjs', import.meta.url))], {
    env: process.env, stdio: ['ignore', 'pipe', 'pipe'],
  })
  let output = ''
  child.stdout.on('data', b => { output += b })
  child.stderr.on('data', b => { output += b })
  const timer = setTimeout(() => child.kill('SIGKILL'), 290_000)
  let code
  try { code = await new Promise((resolve, reject) => { child.on('close', resolve); child.on('error', reject) }) }
  finally { clearTimeout(timer) }
  assert.equal(code, 0, output)
})
