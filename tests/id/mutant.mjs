// Mutation testing of code that runs in a page. Stryker's instrumented code reads the active mutant from
// process.env in Node, which a page has not: `activate` gives it to every page of a browser context. On the first
// (dry) run the pages' coverage is handed back to this process, which the runner reads: `handBack`. A page that
// leaves by itself (the id page answering an application) sends its own as it goes, to its server (tests/id/serve.mjs),
// which calls `take`: nothing can be asked of a page that is navigating away.
export function take (cov) {
  const ns = globalThis.__stryker__
  ns.mutantCoverage ??= { static: {}, perTest: {} }
  for (const [id, n] of Object.entries(cov)) ns.mutantCoverage.static[id] = (ns.mutantCoverage.static[id] ?? 0) + n
}
export const COVERAGE = '/__stryker/coverage'
export async function activate (context) {
  const mutant = process.env.__STRYKER_ACTIVE_MUTANT__
  if (mutant !== undefined) await context.addInitScript((m) => { globalThis.__stryker__ = { activeMutant: m } }, mutant)
  if (globalThis.__stryker__ === undefined) return
  await context.addInitScript((path) => {
    addEventListener('pagehide', () => {
      const cov = globalThis.__stryker__?.mutantCoverage
      if (cov !== undefined) navigator.sendBeacon(location.origin + path, JSON.stringify(cov.static))
    })
  }, COVERAGE)
}

export async function handBack (pages) {
  const ns = globalThis.__stryker__
  if (ns === undefined) return
  for (const frame of pages.flatMap((p) => p.isClosed() ? [] : p.frames())) {
    const cov = await frame.evaluate(() => globalThis.__stryker__?.mutantCoverage).catch(() => undefined)
    if (cov === undefined) continue
    take(cov.static)
  }
}
