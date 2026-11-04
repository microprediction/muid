// The only module through which the witness tests reach the witness: MUID_WITNESS_DIR names a directory holding a
// broken twin of witness/ to run the suite against instead.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const dir = process.env.MUID_WITNESS_DIR ? pathToFileURL(resolve(process.env.MUID_WITNESS_DIR) + '/').href : new URL('../../witness/', import.meta.url).href
export const { witness } = await import(dir + 'witness.js')
export const { witnessService, memoryHoldings, memoryLog } = await import(dir + 'service.js')
