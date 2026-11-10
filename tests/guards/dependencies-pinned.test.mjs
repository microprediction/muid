// Dependencies are pinned: exact versions in package.json, a lockfile that agrees with it, every package from the
// public registry over https with a sha512 integrity, no install scripts, and nothing at runtime but the two noble
// packages. A change to any of these is a deliberate edit here, never a side effect of an install. The one redirect
// allowed is an override that pins a development package to one exact release, as npm's `overrides` is used to take a
// security fix that a dependency has not yet released: never a runtime package, never a range, an alias or a nested
// rule, and every locked copy of the package is that release. The nightly fuzzer's own directory (fuzz/) is held to
// the same rules, with nothing at runtime.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const read = (name) => readFileSync(new URL(`../../${name}`, import.meta.url), 'utf8')
const EXACT = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/
// A locked version is one exact release, a prerelease included; a range never appears there.
const LOCKED = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$/
const SHA512 = /^sha512-[A-Za-z0-9+/]{86}==$/
const RUNTIME = ['@noble/curves', '@noble/hashes']
const REDIRECTS = ['resolutions', 'optionalDependencies', 'peerDependencies', 'bundleDependencies',
  'bundledDependencies', 'workspaces']
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly', 'prepack', 'postpack']
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

// Every fault in the three files, as short strings; none means pinned. `runtime` is what may run outside development.
function faults (pkg, lock, npmrc, runtime = RUNTIME) {
  const out = []
  for (const field of ['dependencies', 'devDependencies']) {
    for (const [name, spec] of Object.entries(pkg[field] ?? {})) if (!EXACT.test(spec)) out.push(`range ${name}`)
  }
  for (const field of REDIRECTS) if (pkg[field] !== undefined) out.push(`field ${field}`)
  for (const [name, spec] of Object.entries(pkg.overrides ?? {})) {
    if (typeof spec !== 'string' || !EXACT.test(spec)) out.push(`override ${name}`)
    if (RUNTIME.includes(name)) out.push(`override runtime ${name}`)
    const copies = Object.entries(lock.packages ?? {}).filter(([path]) => path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length) === name)
    if (copies.length === 0 || copies.some(([, p]) => p.version !== spec)) out.push(`overridden ${name}`)
  }
  for (const hook of INSTALL_HOOKS) if (pkg.scripts?.[hook] !== undefined) out.push(`hook ${hook}`)
  if (!same(Object.keys(pkg.dependencies ?? {}).sort(), runtime)) out.push('runtime dependencies')
  const lines = npmrc.split('\n').map((l) => l.trim())
  for (const line of ['ignore-scripts=true', 'save-exact=true']) if (!lines.includes(line)) out.push(`npmrc ${line}`)

  if (lock.lockfileVersion !== 3) out.push('lockfile version')
  const packages = lock.packages ?? {}
  const top = packages[''] ?? {}
  if (!same(top.dependencies, pkg.dependencies) || !same(top.devDependencies, pkg.devDependencies)) out.push('lock top')
  for (const field of ['dependencies', 'devDependencies']) {
    for (const [name, version] of Object.entries(pkg[field] ?? {})) {
      if (packages[`node_modules/${name}`]?.version !== version) out.push(`locked ${name}`)
    }
  }
  for (const [path, p] of Object.entries(packages)) {
    if (path === '') continue
    if (!path.startsWith('node_modules/')) out.push(`path ${path}`)
    if (typeof p.resolved !== 'string' || !p.resolved.startsWith('https://registry.npmjs.org/')) out.push(`resolved ${path}`)
    if (!SHA512.test(p.integrity ?? '')) out.push(`integrity ${path}`)
    if (p.hasInstallScript !== undefined) out.push(`install script ${path}`)
    if (p.link !== undefined) out.push(`link ${path}`)
    if (!LOCKED.test(p.version ?? '')) out.push(`version ${path}`)
  }
  const closure = Object.entries(packages).filter(([path, p]) => path !== '' && p.dev !== true).map(([path]) => path).sort()
  if (!same(closure, runtime.map((n) => `node_modules/${n}`))) out.push('runtime closure')
  if (runtime.length === 0) return out
  if (!same(packages['node_modules/@noble/curves']?.dependencies, { '@noble/hashes': pkg.dependencies?.['@noble/hashes'] })) {
    out.push('curves dependencies')
  }
  if (packages['node_modules/@noble/hashes']?.dependencies !== undefined) out.push('hashes dependencies')
  return out
}

const PKG = JSON.parse(read('package.json'))
const LOCK = JSON.parse(read('package-lock.json'))
const NPMRC = read('.npmrc')

test('the repository is pinned', () => {
  assert.ok(Object.keys(LOCK.packages).length > 3)
  assert.deepEqual(faults(PKG, LOCK, NPMRC), [])
})

const FUZZ = { pkg: JSON.parse(read('fuzz/package.json')), lock: JSON.parse(read('fuzz/package-lock.json')), npmrc: read('fuzz/.npmrc') }

test('the fuzzer\'s directory is pinned, with nothing at runtime', () => {
  assert.ok(Object.keys(FUZZ.lock.packages).length > 3)
  assert.deepEqual(faults(FUZZ.pkg, FUZZ.lock, FUZZ.npmrc, []), [])
  assert.equal(FUZZ.npmrc, NPMRC, 'the same npm configuration as the repository\'s')
})

test('the guard catches a fuzzer dependency at runtime, a range, or an install script', () => {
  const f = JSON.parse(JSON.stringify(FUZZ))
  const any = Object.keys(f.lock.packages).find((p) => p !== '')
  f.pkg.dependencies = { x: '1.0.0' }
  f.pkg.devDependencies['@jazzer.js/core'] = '^4.0.0'
  f.lock.packages[any].hasInstallScript = true
  delete f.lock.packages[any].dev
  const found = faults(f.pkg, f.lock, f.npmrc, [])
  for (const fault of ['runtime dependencies', 'range @jazzer.js/core', `install script ${any}`, 'runtime closure']) assert.ok(found.includes(fault), fault)
})

// The guard's own broken twins: each edit to a copy of the real files must produce the fault named.
const copy = () => JSON.parse(JSON.stringify({ pkg: PKG, lock: LOCK }))
const ANY = Object.keys(LOCK.packages).find((p) => p !== '' && LOCK.packages[p].dev === true)
const TWINS = [
  ['a caret range', (f) => { f.pkg.devDependencies['fast-check'] = '^' + f.pkg.devDependencies['fast-check'] }, 'range fast-check'],
  ['a tilde range', (f) => { f.pkg.dependencies['@noble/hashes'] = '~2.4.0' }, 'range @noble/hashes'],
  ['a git dependency', (f) => { f.pkg.devDependencies.x = 'github:a/b' }, 'range x'],
  ['a resolutions field', (f) => { f.pkg.resolutions = {} }, 'field resolutions'],
  ['an override to a range', (f) => { f.pkg.overrides = { qs: '^6.16.2' } }, 'override qs'],
  ['an override to an alias', (f) => { f.pkg.overrides = { qs: 'npm:other@6.16.2' } }, 'override qs'],
  ['a nested override', (f) => { f.pkg.overrides = { '@stryker-mutator/core': { qs: '6.16.2' } } }, 'override @stryker-mutator/core'],
  ['an override of a runtime package', (f) => { f.pkg.overrides = { '@noble/hashes': f.pkg.dependencies['@noble/hashes'] } }, 'override runtime @noble/hashes'],
  ['an override the lock disagrees with', (f) => { f.pkg.overrides = { qs: '6.16.2' }; f.lock.packages['node_modules/qs'].version = '6.15.1' }, 'overridden qs'],
  ['an override of a package not locked', (f) => { f.pkg.overrides = { x: '1.0.0' } }, 'overridden x'],
  ['a postinstall', (f) => { f.pkg.scripts.postinstall = 'x' }, 'hook postinstall'],
  ['a third runtime dependency', (f) => { f.pkg.dependencies.x = '1.0.0' }, 'runtime dependencies'],
  ['lockfile version 2', (f) => { f.lock.lockfileVersion = 2 }, 'lockfile version'],
  ['the lock top disagrees', (f) => { f.lock.packages[''].devDependencies = {} }, 'lock top'],
  ['a locked version that differs', (f) => { f.lock.packages['node_modules/fast-check'].version = '4.0.0' }, 'locked fast-check'],
  ['another registry', (f) => { f.lock.packages[ANY].resolved = 'https://registry.example/x.tgz' }, `resolved ${ANY}`],
  ['plain http', (f) => { f.lock.packages[ANY].resolved = f.lock.packages[ANY].resolved.replace('https:', 'http:') }, `resolved ${ANY}`],
  ['sha1 integrity', (f) => { f.lock.packages[ANY].integrity = 'sha1-' + 'A'.repeat(27) + '=' }, `integrity ${ANY}`],
  ['an install script', (f) => { f.lock.packages[ANY].hasInstallScript = true }, `install script ${ANY}`],
  ['a link', (f) => { f.lock.packages[ANY].link = true }, `link ${ANY}`],
  ['a range in the lock', (f) => { f.lock.packages[ANY].version = '^1.0.0' }, `version ${ANY}`],
  ['a dev package at runtime', (f) => { delete f.lock.packages[ANY].dev }, 'runtime closure'],
  ['curves on another hashes', (f) => { f.lock.packages['node_modules/@noble/curves'].dependencies['@noble/hashes'] = '2.0.0' }, 'curves dependencies'],
  ['hashes with a dependency', (f) => { f.lock.packages['node_modules/@noble/hashes'].dependencies = { x: '1.0.0' } }, 'hashes dependencies'],
]

for (const [name, edit, fault] of TWINS) {
  test(`the guard catches ${name}`, () => {
    const f = copy()
    edit(f)
    assert.ok(faults(f.pkg, f.lock, NPMRC).includes(fault), fault)
  })
}

test('the guard catches an .npmrc without ignore-scripts or save-exact', () => {
  assert.ok(faults(PKG, LOCK, NPMRC.replace('ignore-scripts=true', '')).includes('npmrc ignore-scripts=true'))
  assert.ok(faults(PKG, LOCK, NPMRC.replace('save-exact=true', 'save-exact=false')).includes('npmrc save-exact=true'))
})
