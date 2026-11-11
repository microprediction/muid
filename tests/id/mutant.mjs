// Mutation testing of code that runs in a page. Stryker's instrumented code reads the active mutant from
// process.env in Node, which a page has not: `activate` gives it to every page of a browser context. On the first
// (dry) run the pages' coverage is handed back to this process, which the runner reads: `handBack`.
export async function activate (context) {
  const mutant = process.env.__STRYKER_ACTIVE_MUTANT__
  if (mutant !== undefined) await context.addInitScript((m) => { globalThis.__stryker__ = { activeMutant: m } }, mutant)
}

export async function handBack (pages) {
  const ns = globalThis.__stryker__
  if (ns === undefined) return
  for (const frame of pages.flatMap((p) => p.isClosed() ? [] : p.frames())) {
    const cov = await frame.evaluate(() => globalThis.__stryker__?.mutantCoverage).catch(() => undefined)
    if (cov === undefined) continue
    ns.mutantCoverage ??= { static: {}, perTest: {} }
    for (const [id, n] of Object.entries(cov.static)) ns.mutantCoverage.static[id] = (ns.mutantCoverage.static[id] ?? 0) + n
  }
}
