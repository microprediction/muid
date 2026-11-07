// fast-check's run count for a property whose usual count is n (SPEC §12). FC_RUNS sets every count outright
// (mutation testing and the twins lower it; a replay sets it); FC_SCALE multiplies each file's own count, so the
// nightly run gives every property the same multiple of its usual budget.
export function runs(n) {
  const { FC_RUNS, FC_SCALE } = process.env
  const positive = (x) => Number.isSafeInteger(x) && x > 0
  const value = FC_RUNS !== undefined ? Number(FC_RUNS) : FC_SCALE !== undefined ? Number(FC_SCALE) : 1
  if (!positive(value)) throw new RangeError('FC_RUNS and FC_SCALE are positive integers')
  return FC_RUNS !== undefined ? value : n * value
}
