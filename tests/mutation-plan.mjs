// Which Stryker configs a change can affect, and the CI jobs they run in. A config's inputs are the files it mutates,
// its test files, and everything those reach through a relative path written in them (an import, a URL, a directory
// served or read), followed transitively; a path into a directory takes the whole directory, and a path that stops at
// a template's `${` takes the directory before it. Package files, this file and the workflow are inputs of every
// config. A pull request runs the quick configs whose inputs it changes, a push to master every quick config, and the
// nightly and manual runs every config.
//
//   node tests/mutation-plan.mjs              prints the jobs as JSON: the quick configs
//   node tests/mutation-plan.mjs changed.txt  the quick configs that the paths listed in changed.txt affect
//   node tests/mutation-plan.mjs --nightly    every config
import { readFileSync, readdirSync, statSync, existsSync, globSync } from 'node:fs'
import { join, dirname, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('../', import.meta.url))
const GLOBAL = ['package.json', 'package-lock.json', '.github/workflows/test.yml', 'tests/mutation-plan.mjs']

// Every pull request and push runs this job, for the configs the change affects: quick enough to wait for.
export const EVERY_RUN = ['stryker.id-records.config.json', 'stryker.adapter.config.json', 'stryker.receipt.config.json',
  'stryker.note.config.json', 'stryker.ed25519.config.json', 'stryker.root.config.json', 'stryker.p256.config.json',
  'stryker.origin.config.json', 'stryker.merkle.config.json', 'stryker.envelope.config.json',
  'stryker.delegation.config.json', 'stryker.bytes.config.json', 'stryker.attestation.config.json',
  'stryker.assertion.config.json']

// The nightly (and manual) run adds these: the slow configs alone, the others together.
export const NIGHTLY = [
  ['stryker.id-page.config.json'],
  ['stryker.membership.config.json'],
  ['stryker.witness.config.json'],
  ['stryker.verifier.config.json', 'stryker.config.json', 'stryker.demo.config.json'],
]

export const JOBS = [...NIGHTLY, EVERY_RUN]

const rel = (abs) => relative(ROOT, abs).split(sep).join('/')
const isDir = (abs) => existsSync(abs) && statSync(abs).isDirectory()
const filesUnder = (abs) => readdirSync(abs, { recursive: true }).map((f) => join(abs, f)).filter((f) => !isDir(f))
const EVERYTHING = '*'
const SCANNED = /\.(m?js)$/

// The repository paths a file names: each quoted or template string starting ./ or ../, resolved against the file.
export function references (abs, text) {
  const out = []
  for (const [, path, stop] of text.matchAll(/['`](\.\.?\/[^'`$\n]*)(['`$])/g)) {
    const named = stop === '$' ? path.slice(0, path.lastIndexOf('/') + 1) : path
    out.push(resolve(dirname(abs), named) + (named.endsWith('/') ? sep : ''))
  }
  return out
}

// Every repository file and directory (ending /) that runs from these files can read, root-relative and sorted; ['*']
// if they name the whole repository. A missing file is kept, so deleting a file still named counts as a change to it,
// and a directory covers every path under it, including files added or deleted.
export function reach (files) {
  const seen = new Set()
  const queue = files.map((f) => join(ROOT, f))
  while (queue.length > 0) {
    const abs = queue.pop()
    const r = rel(abs)
    if (r === '') return [EVERYTHING]
    if (r.startsWith('..') || r === 'node_modules' || r.startsWith('node_modules/')) continue
    const dir = isDir(abs) || abs.endsWith(sep)
    if (dir) {
      const d = abs.endsWith(sep) ? abs : abs + sep
      if (seen.has(d)) continue
      seen.add(d)
    }
    for (const f of dir ? (isDir(abs) ? filesUnder(abs) : []) : [abs]) {
      if (seen.has(f)) continue
      seen.add(f)
      if (SCANNED.test(f) && existsSync(f)) queue.push(...references(f, readFileSync(f, 'utf8')))
    }
  }
  return [...seen].map((f) => rel(f) + (f.endsWith(sep) ? '/' : '')).sort()
}

// A config's inputs: what its mutated and test files reach, the config itself, and the files every config reads.
export function inputs (name) {
  const config = JSON.parse(readFileSync(join(ROOT, name), 'utf8'))
  const reached = reach([...config.mutate, ...config.tap.testFiles.flatMap((g) => globSync(g, { cwd: ROOT }))])
  return [...new Set([name, ...GLOBAL, ...reached])].sort()
}

// Whether a change to the listed paths changes an input (a file, a directory ending /, or everything).
export const touches = (input, changed) => input === EVERYTHING || (input.endsWith('/') ? changed.some((c) => c.startsWith(input)) : changed.includes(input))

// Of these jobs, the configs a change to the listed paths affects (all of them for null), as space-separated lists.
export function select (changed, jobs = JOBS) {
  const affected = (c) => changed === null || inputs(c).some((f) => touches(f, changed))
  return jobs.map((job) => job.filter(affected)).filter((job) => job.length > 0).map((job) => job.join(' '))
}

// The jobs to run: every job nightly; otherwise the every-run job, for the configs the change affects (null: all).
export const plan = (changed, { nightly = false } = {}) => nightly ? select(null) : select(changed, [EVERY_RUN])

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const arg = process.argv[2]
  const nightly = arg === '--nightly'
  const changed = arg === undefined || nightly ? null : readFileSync(arg, 'utf8').split('\n').filter((l) => l !== '')
  process.stdout.write(JSON.stringify(plan(changed, { nightly })) + '\n')
}
