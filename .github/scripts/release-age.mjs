// SPEC §12 release-age cooldown: fails if any package in a lockfile (the repository's, the fuzzer's) was published less than MIN_DAYS ago.
// npm's min-release-age (.npmrc) applies when versions are chosen; `npm ci` installs the lockfile as it is, so this
// check is what holds the lockfile to it. Network access: the public registry only.
import { readFileSync } from 'node:fs'

const MIN_DAYS = 7
// The repository's lockfile and the nightly fuzzer's (fuzz/).
const wanted = new Map()
for (const file of ['../../package-lock.json', '../../fuzz/package-lock.json']) {
  const lock = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'))
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === '' || entry.link) continue
    const name = entry.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length)
    if (!wanted.has(name)) wanted.set(name, new Set())
    wanted.get(name).add(entry.version)
  }
}

const now = Date.now()
const problems = []
const names = [...wanted.keys()]
async function check (name) {
  const res = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2f')}`, { headers: { accept: 'application/json' } })
  if (!res.ok) { problems.push(`${name}: registry answered ${res.status}`); return }
  const { time = {} } = await res.json()
  for (const version of wanted.get(name)) {
    const published = Date.parse(time[version])
    if (Number.isNaN(published)) problems.push(`${name}@${version}: no publish time`)
    else if (now - published < MIN_DAYS * 86_400_000) problems.push(`${name}@${version}: published ${time[version]}`)
  }
}
for (let i = 0; i < names.length; i += 8) await Promise.all(names.slice(i, i + 8).map(check))
if (problems.length > 0) {
  console.error(`Published less than ${MIN_DAYS} days ago, or not checkable:\n  ${problems.join('\n  ')}`)
  process.exit(1)
}
console.log(`${names.length} packages, every version public for at least ${MIN_DAYS} days`)
