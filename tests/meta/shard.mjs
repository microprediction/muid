// MUID_TWIN_SHARD=k/n keeps the k-th of n parts of a harness's twins (every n-th from the k-th); unset or empty, all.
// The nightly job runs the parts side by side, a runner each, since one runner takes the id twins one at a time and
// did not finish them inside two hours.
export function part (jobs, text = process.env.MUID_TWIN_SHARD ?? '') {
  if (text === '') return [...jobs]
  const m = /^([1-9]\d*)\/([1-9]\d*)$/.exec(text)
  if (m === null || Number(m[1]) > Number(m[2])) throw new RangeError('MUID_TWIN_SHARD is k/n, with 1 <= k <= n')
  return jobs.filter((_, i) => i % Number(m[2]) === Number(m[1]) - 1)
}
