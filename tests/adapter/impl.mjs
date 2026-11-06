// The only module through which the adapter tests reach the adapter: MUID_ADAPTER_DIR names a directory holding a
// broken twin of adapter/ to run the suite against instead.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const dir = process.env.MUID_ADAPTER_DIR ? pathToFileURL(resolve(process.env.MUID_ADAPTER_DIR) + '/').href : new URL('../../adapter/', import.meta.url).href
export const urls = { adapter: dir + 'relying-party.js', stores: dir + 'stores.js' }
export const { relyingParty } = await import(urls.adapter)
export const { memoryStore, sqliteStore } = await import(urls.stores)
