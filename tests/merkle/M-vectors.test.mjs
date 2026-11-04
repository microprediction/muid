// RFC 9162 §2.1.3.2 and §2.1.4.2 against transparency-dev/merkle's vectors: each set's valid proof is accepted and
// every corruption of it (a changed index or size, a flipped bit, a truncated, extended or empty proof, a wrong or
// swapped root) is refused.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { merkle } from '../impl.mjs'

const { verifyInclusion, verifyConsistency } = merkle
const ROOT = new URL('../vectors/tlog-merkle/', import.meta.url).pathname
const files = (dir) => readdirSync(dir).flatMap((n) => statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : n.endsWith('.json') ? [join(dir, n)] : [])
const bytes = (b64) => (b64 === null || b64 === undefined ? b64 : new Uint8Array(Buffer.from(b64, 'base64')))
const proof = (p) => (p === null ? [] : p.map(bytes))

// Known differences, each refused here and accepted upstream: every hash here is 32 bytes (SHA-256), where upstream
// compares placeholder roots of any length when the sizes are equal.
const KNOWN = new Set(['consistency/additional/sizes-are-equal-one-and-proof-is-empty.json'])

for (const kind of ['inclusion', 'consistency']) {
  test(`${kind}: every vector gives its expected answer`, () => {
    const all = files(join(ROOT, kind))
    let valid = 0
    for (const f of all) {
      const v = JSON.parse(readFileSync(f, 'utf8'))
      const ok = kind === 'inclusion'
        ? verifyInclusion({ leafHash: bytes(v.leafHash), index: v.leafIdx, size: v.treeSize, proof: proof(v.proof), root: bytes(v.root) })
        : verifyConsistency({ size1: v.size1, size2: v.size2, root1: bytes(v.root1), root2: bytes(v.root2), proof: proof(v.proof) })
      const name = relative(ROOT, f)
      assert.equal(ok, KNOWN.has(name) ? false : !v.wantErr, `${name}: ${v.desc}`)
      if (KNOWN.has(name)) assert.equal(v.wantErr, false, `${name} is still a difference`)
      if (ok) valid++
    }
    // Anti-vacuity: the loaded counts, so a lost file or a vector that stops loading is noticed.
    assert.deepEqual([all.length, valid], [98, kind === 'inclusion' ? 6 : 5])
  })
}
