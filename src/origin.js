// Canonical https origins (SPEC §5 O1), by a fixed grammar rather than a URL parser, so that every engine agrees.
const { apply } = Reflect
const { exec } = RegExp.prototype
const { split } = String.prototype

// https://host[:port], with the port 1–65535, no leading zero, checked numerically below.
const SHAPE = /^https:\/\/([a-z0-9.-]{1,253})(?::([1-9][0-9]{0,4}))?$/
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const DIGITS = /^[0-9]+$/

function labelOk (label) {
  // No "??--" label: that form is reserved for IDNA (xn--), which this version refuses.
  return apply(exec, LABEL, [label]) !== null && !(label[2] === '-' && label[3] === '-')
}

export function isCanonicalOrigin (x) {
  if (typeof x !== 'string') return false
  const m = apply(exec, SHAPE, [x])
  if (m === null) return false
  if (+m[2] > 65535 || m[2] === '443') return false // an absent port is NaN here, and passes
  const labels = apply(split, m[1], ['.'])
  if (labels.length < 2) return false // at most 127 follows from the 253-character limit
  for (let i = 0; i < labels.length; i++) if (!labelOk(labels[i])) return false
  return apply(exec, DIGITS, [labels[labels.length - 1]]) === null
}
