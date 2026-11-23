// tests/meta/suite.mjs ends a suite with everything it started. A suite here is a process that opens Chrome, as the
// page's tests do, and then never finishes; a twin harness ends such a suite when it hangs, and whatever it runs when
// it is itself told to stop.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { start, end } from '../meta/suite.mjs'

// A suite that opens a browser and says its pid, and a harness that runs it; `done()` removes them.
function scripts () {
  const dir = mkdtempSync(join(tmpdir(), 'muid-suite-end-'))
  const suite = join(dir, 'suite.mjs')
  const harness = join(dir, 'harness.mjs')
  writeFileSync(suite, `import { chromium } from ${JSON.stringify(import.meta.resolve('playwright-core'))}
const browser = await chromium.launchServer({ channel: 'chrome', headless: true }) // started as launch starts it
console.log('browser', browser.process().pid)
setInterval(() => {}, 1000)
`)
  writeFileSync(harness, `import { start } from ${JSON.stringify(import.meta.resolve('../meta/suite.mjs'))}
start([${JSON.stringify(suite)}], { stdio: ['ignore', 'inherit', 'inherit'] })
setInterval(() => {}, 1000)
`)
  return { suite, harness, done: () => rmSync(dir, { recursive: true, force: true }) }
}

const alive = (pid) => { try { process.kill(pid, 0); return true } catch { return false } }
const gone = async (pid) => { for (let i = 0; i < 200 && alive(pid); i++) await new Promise((resolve) => setTimeout(resolve, 50)); return !alive(pid) }
// The pid of the browser the process opened, once it says it has.
const browserOf = (child) => new Promise((resolve, reject) => {
  let out = ''
  child.stdout.on('data', (d) => {
    out += d
    const m = /^browser (\d+)$/m.exec(out)
    if (m !== null) resolve(Number(m[1]))
  })
  child.on('close', () => reject(new Error(`ended before it opened a browser: ${out}`)))
})

test('a suite is ended with the browser it opened; killing its process group alone leaves the browser running', { timeout: 120_000 }, async () => {
  const s = scripts()
  try {
    // The control: the group killed outright, as the harnesses did, and the browser is still running.
    const before = start([s.suite], { stdio: ['ignore', 'pipe', 'inherit'] })
    const left = await browserOf(before)
    process.kill(-before.pid, 'SIGKILL')
    assert.equal(await gone(before.pid), true)
    assert.equal(alive(left), true, 'the browser outlives its group')
    process.kill(left, 'SIGKILL')
    assert.equal(await gone(left), true)
    // Ended: the suite and its browser.
    const child = start([s.suite], { stdio: ['ignore', 'pipe', 'inherit'] })
    const browser = await browserOf(child)
    assert.equal(alive(browser), true)
    end(child)
    assert.deepEqual([await gone(child.pid), await gone(browser)], [true, true])
  } finally { s.done() }
})

test('a harness told to stop ends the suite it runs, and the browser that suite opened', { timeout: 120_000 }, async () => {
  const s = scripts()
  try {
    const harness = start([s.harness], { stdio: ['ignore', 'pipe', 'inherit'] }) // and ended, should this test fail
    const browser = await browserOf(harness)
    harness.kill('SIGTERM')
    assert.equal(await gone(harness.pid), true)
    assert.equal(await gone(browser), true, 'the browser is ended with the harness')
  } finally { s.done() }
})
