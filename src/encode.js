// Placeholder. The tests in tests/encoding/ are committed first and must fail against this file.
export class EncodingError extends Error {
  constructor (reason) {
    super(reason)
    this.reason = reason
  }
}

export const MAX_BYTES = 0
export const MAX_DEPTH = 0

export function encode () {
  throw new Error('not implemented')
}

export function decode () {
  throw new Error('not implemented')
}
