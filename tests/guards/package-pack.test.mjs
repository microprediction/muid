// R1 scenario 158: "private" prevents publication but does not prevent npm pack.
// Check the actual tarball manifest, not just the package's export map.
// This is intentionally run in ordinary CI, not only in a publishing workflow.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const ROOT = new URL('../../', import.meta.url).pathname

test('npm pack contains every exported module but no test, model or research files', () => {
  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))
  const report = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    maxBuffer: 8 * 1024 * 1024,
  }))
  assert.equal(report.length, 1)
  const files = new Set(report[0].files.map((item) => item.path))
  assert.ok(files.has('package.json'), 'package manifest is packed')
  for (const [entry, target] of Object.entries(pkg.exports)) {
    const path = target.replace(/^\.\//, '')
    assert.ok(files.has(path), `${entry} -> ${path} must be packed`)
  }
  for (const path of files) {
    assert.doesNotMatch(path, /^(?:tests|model|research)\//, `${path} must not be packed`)
  }
})
