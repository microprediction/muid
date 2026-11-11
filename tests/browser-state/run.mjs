import assert from 'node:assert/strict'
import fc from 'fast-check'
import { explore, operations, run } from './histories.mjs'
import { controls, freshReadRepairControl } from './controls.mjs'

const format = a => a.type === 'reply' ? `reply(${a.tab},${a.kind},${a.outcome ?? 'ok'})`
  : a.type === 'edit' ? `edit(${a.tab},${a.field})`
    : `${a.type}(${a.tab ?? ''}${a.family ? ',' + a.family : ''}${a.row !== undefined ? ',row=' + a.row : ''})`
const began = performance.now()
await controls()
const result = await explore()
console.log(`Bounded exploration: ${result.histories} histories, ${result.transitions} transitions`)
for (const [name, f] of result.found) console.log(`\n${name}: ${f.message}\n  ${f.pair}\n  ${f.trace.map(format).join(' -> ')}`)

// Longer generated histories supplement pairwise exploration. In particular a
// property failure is shrunk by fast-check to a smaller supported history.
const commands = [...Object.values(operations(0)).flat(), ...Object.values(operations(1)).flat()]
const seed = Number(process.env.FC_SEED ?? 71071)
const details = await fc.check(fc.asyncProperty(fc.array(fc.constantFrom(...commands), { minLength: 1, maxLength: 24 }), async actions => {
  const h = await run(actions)
  assert.deepEqual(h.failures, [], 'browser history violates its contract')
}), { seed, numRuns: Number(process.env.FC_RUNS ?? 100) })
if (details.failed) {
  const actions = details.counterexample[0]
  const h = await run(actions)
  console.log(`\nGenerated history failed (seed=${details.seed}, path=${details.counterexamplePath}):\n  ${actions.map(format).join(' -> ')}`)
  for (const f of h.failures) { console.log(`  ${f.contract}: ${f.message}`); if (!result.found.has(f.contract)) result.found.set(f.contract, f) }
} else console.log(`\nGenerated histories: ${details.numRuns} passed (seed=${seed})`)
console.log(`\nElapsed: ${Math.round(performance.now() - began)} ms`)

if (process.argv.includes('--calibrate')) {
  // Diagnostic for the reviewed PR #71 revision, not an assertion that these
  // bugs should remain. The normal CI entry point below requires no findings.
  for (const name of ['storage-history', 'persistence', 'review-cancellation']) assert.ok(result.found.has(name), `missed the known ${name} regression`)
  await freshReadRepairControl()
  console.log('\nCalibration: all three previously missed contracts were rediscovered.')
} else if (result.found.size || details.failed) process.exitCode = 1
