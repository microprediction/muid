// The only module through which the worker tests reach worker/: MUID_WORKER_DIR names a directory holding a broken twin.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const dir = process.env.MUID_WORKER_DIR ? pathToFileURL(resolve(process.env.MUID_WORKER_DIR) + '/').href : new URL('../../worker/', import.meta.url).href
export const { newKey, subjectOf, accept, enrol, claim, request } = await import(dir + 'worker.js')
