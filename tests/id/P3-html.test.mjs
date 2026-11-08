// The page's HTML: its one inline script is the import map, allowed by its hash in the CSP; everything else comes
// from the page's own origin, and nothing may frame or post it elsewhere.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dir } from './impl.mjs'

const html = readFileSync(new URL('index.html', dir), 'utf8')

test('the CSP allows exactly the import map inline, by its hash, and nothing from elsewhere', () => {
  const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
  const inline = scripts.filter(([, attrs]) => !/\bsrc=/.test(attrs))
  assert.equal(inline.length, 1)
  assert.match(inline[0][1], /type="importmap"/)
  const map = JSON.parse(inline[0][2])
  assert.deepEqual(Object.keys(map.imports).sort(), ['@noble/curves/', '@noble/hashes/'])
  for (const target of Object.values(map.imports)) assert.match(target, /^\/node_modules\/@noble\/[a-z]+\/$/)
  const csp = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)[1]
  const hash = createHash('sha256').update(inline[0][2]).digest('base64')
  assert.equal(csp, `default-src 'none'; script-src 'self' 'sha256-${hash}'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'`)
  assert.doesNotMatch(html, /(?:src|href)="(?![a-z.]+")/, 'every script and stylesheet is a file beside the page')
  assert.doesNotMatch(html, / on[a-z]+=/, 'no inline event handlers')
})
