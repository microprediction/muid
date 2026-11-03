// SPEC §12 "CI hardening" and "Supply chain": every workflow pins actions by commit SHA, holds a read-only token,
// never runs on pull_request_target, never persists checkout credentials, and installs without install scripts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const DIR = new URL('../../.github/workflows/', import.meta.url).pathname

export function problems (yaml) {
  const out = []
  const lines = yaml.split('\n')
  for (const [n, raw] of lines.entries()) {
    const line = raw.replace(/\s+#.*$/, '')
    const uses = line.match(/^\s*-?\s*uses:\s*(\S+)/)
    if (uses && !/^[\w.-]+\/[\w.-]+(?:\/[\w./-]+)?@[0-9a-f]{40}$/.test(uses[1])) out.push(`line ${n + 1}: action not pinned by commit SHA: ${uses[1]}`)
    if (/\bpull_request_target\b/.test(line)) out.push(`line ${n + 1}: pull_request_target`)
    if (/:\s*write\b/.test(line)) out.push(`line ${n + 1}: write permission`)
    if (/\bnpm\s+(?:install|i)\b/.test(line)) out.push(`line ${n + 1}: npm install (use npm ci --ignore-scripts)`)
    if (/\bnpm\s+ci\b/.test(line) && !/--ignore-scripts\b/.test(line)) out.push(`line ${n + 1}: npm ci without --ignore-scripts`)
    if (/uses:\s*actions\/checkout@/.test(line)) {
      const block = lines.slice(n + 1, n + 4).join('\n')
      if (!/persist-credentials:\s*false/.test(block)) out.push(`line ${n + 1}: checkout without persist-credentials: false`)
    }
  }
  if (!/^permissions:\s*\n\s+contents:\s*read\s*$/m.test(yaml)) out.push('no top-level read-only permissions block')
  return out
}

test('every workflow is hardened', () => {
  const files = readdirSync(DIR).filter((f) => /\.ya?ml$/.test(f))
  assert.ok(files.length >= 1, 'found the workflows')
  const all = files.flatMap((f) => problems(readFileSync(join(DIR, f), 'utf8')).map((p) => `${f}: ${p}`))
  assert.deepEqual(all, [])
})

test('the checks fire on each violation', () => {
  const ok = 'permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@' + 'a'.repeat(40) + '\n        with:\n          persist-credentials: false\n      - run: npm ci --ignore-scripts\n'
  assert.deepEqual(problems(ok), [])
  const bad = {
    'tag pin': ok.replace('@' + 'a'.repeat(40), '@v4'),
    'short sha': ok.replace('a'.repeat(40), 'a'.repeat(7)),
    'pull_request_target': 'on: pull_request_target\n' + ok,
    'write permission': ok.replace('contents: read', 'contents: read\n  issues: write'),
    'npm install': ok + '      - run: npm install\n',
    'npm ci with scripts': ok.replace('npm ci --ignore-scripts', 'npm ci'),
    'persisted credentials': ok.replace('persist-credentials: false', 'fetch-depth: 1'),
    'no permissions block': ok.replace('permissions:\n  contents: read\n', ''),
  }
  for (const [label, yaml] of Object.entries(bad)) assert.ok(problems(yaml).length > 0, label)
})
