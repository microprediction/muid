// The only module through which the demo tests reach demo/: MUID_DEMO_DIR names a directory holding a broken twin.
import { pathToFileURL } from 'node:url'
import { resolve } from 'node:path'

const dir = process.env.MUID_DEMO_DIR ? pathToFileURL(resolve(process.env.MUID_DEMO_DIR) + '/').href : new URL('../../demo/', import.meta.url).href
export const { forecasts } = await import(dir + 'forecasts.js')
export const { history } = await import(dir + 'history.js')
