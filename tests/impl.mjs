// The only module through which tests reach the implementation (TESTING.md §6).
// MUID_ENCODING_IMPL, MUID_ENVELOPE_IMPL and MUID_ED25519_IMPL name a broken twin to run a suite against instead of
// the real module. A module not written yet fails its own tests on first use without breaking the other suites.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'
import { existsSync } from 'node:fs'

async function load (variable, path) {
  const override = process.env[variable]
  if (override) return import(pathToFileURL(resolve(override)).href)
  const url = new URL(path, import.meta.url)
  if (existsSync(url)) return import(url.href)
  // `then` is probed by await; every other property access fails the test that makes it.
  return new Proxy({}, {
    get (_, k) {
      if (k === 'then') return undefined
      throw new Error(`${path} is not written yet (${String(k)})`)
    },
  })
}

export const encoding = await load('MUID_ENCODING_IMPL', '../src/encode.js')
export const envelope = await load('MUID_ENVELOPE_IMPL', '../src/envelope.js')
export const ed25519 = await load('MUID_ED25519_IMPL', '../src/ed25519.js')
export const p256 = await load('MUID_P256_IMPL', '../src/p256.js')
export const assertion = await load('MUID_ASSERTION_IMPL', '../src/assertion.js')
