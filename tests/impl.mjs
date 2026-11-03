// The only module through which tests reach the implementation (TESTING.md §4).
// MUID_ENCODING_IMPL names a broken twin to run the whole suite against instead of src/encode.js.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const override = process.env.MUID_ENCODING_IMPL
const url = override ? pathToFileURL(resolve(override)).href : new URL('../src/encode.js', import.meta.url).href

export const encoding = await import(url)
