// Fails if any SARIF file under the given directory holds a result, printing each one.
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const dir = process.argv[2]
const files = readdirSync(dir).filter((f) => f.endsWith('.sarif'))
if (files.length === 0) { console.error(`no SARIF files in ${dir}`); process.exit(1) }
let results = 0
for (const f of files) {
  for (const run of JSON.parse(readFileSync(join(dir, f), 'utf8')).runs) {
    for (const r of run.results ?? []) {
      results++
      const loc = r.locations?.[0]?.physicalLocation
      console.error(`${r.ruleId}: ${loc?.artifactLocation?.uri}:${loc?.region?.startLine}: ${r.message?.text}`)
    }
  }
}
console.log(`${files.length} SARIF file(s), ${results} result(s)`)
process.exit(results === 0 ? 0 : 1)
