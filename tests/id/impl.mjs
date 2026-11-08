// The only module through which the id page tests reach id/: MUID_ID_DIR names a directory holding a broken twin.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

export const dir = process.env.MUID_ID_DIR ? pathToFileURL(resolve(process.env.MUID_ID_DIR) + '/').href : new URL('../../id/', import.meta.url).href
export const records = await import(dir + 'records.js')
