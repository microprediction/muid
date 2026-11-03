// The only module through which tests reach the implementation (TESTING.md §5).
// MUID_ENCODING_IMPL and MUID_ENVELOPE_IMPL name a broken twin to run the suite against instead of the real module.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'
import { existsSync } from 'node:fs'

const override = process.env.MUID_ENCODING_IMPL
const url = override ? pathToFileURL(resolve(override)).href : new URL('../src/encode.js', import.meta.url).href

export const encoding = await import(url)

// Until src/envelope.js exists its tests fail on first use, without breaking the encoding suite.
const envelopeOverride = process.env.MUID_ENVELOPE_IMPL
const envelopeUrl = envelopeOverride
  ? pathToFileURL(resolve(envelopeOverride)).href
  : new URL('../src/envelope.js', import.meta.url).href
export const envelope = envelopeOverride || existsSync(new URL(envelopeUrl))
  ? await import(envelopeUrl)
  : new Proxy({}, { get (_, k) { throw new Error(`src/envelope.js is not written yet (${String(k)})`) } })
