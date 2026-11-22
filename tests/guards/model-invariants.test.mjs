// SPEC §12 / review scenario 153: pin the invariants the state models promise to check.
// Their presence in a model file is not enough: a CI-executed TLC configuration must name each one.
// This manifest is deliberately separate from the model and its cfg so deleting a check in both cannot go unnoticed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8')

// TypeOK is included where defined, in addition to the safety invariants named in the models' headers.
const REQUIRED = {
  IdPage: ['TypeOK', 'OneKeyPerAgent', 'NoLostUpdate', 'NoResurrection', 'ViewHonest', 'NoRevival',
    'ShownIsSaved', 'ReviewedStateIsCurrent', 'SavedBeforeHandover', 'Unexpired'],
  IdRoot: ['TypeOK', 'NeverOverwritten', 'JoiningNeverRegistered', 'MarkedIsTaken', 'MemberIsCosigned',
    'CardIsKept', 'SaltsBounded'],
  Adapter: ['TypeOK', 'NoRevival', 'AtMostOnce', 'NoExpiredAuthorizationAtCommit', 'FreshnessBound'],
  WitnessOutbox: ['NoRival', 'ServedIsLogged', 'HeldIsLogged', 'LogInOrder', 'HeldIsChain'],
}
const RUNNER = {
  IdPage: 'MCIdPage',
  IdRoot: 'IdRoot',
  Adapter: 'MCAdapter',
  WitnessOutbox: 'WitnessOutbox',
}

// Return every required invariant either not defined in the model or not selected by the checked configuration.
function missing (model, cfg, required) {
  const line = cfg.match(/^[ \t]*INVARIANTS[ \t]+([^\r\n]+)$/m)
  const checked = new Set((line?.[1] ?? '').trim().split(/\s+/).filter(Boolean))
  return required.filter((name) => !new RegExp(`^${name}[ \\t]*==`, 'm').test(model) || !checked.has(name))
}

test('each promised invariant is defined and checked by a CI-run TLC configuration', () => {
  const script = read('.github/scripts/tlc.sh')
  for (const [model, expected] of Object.entries(REQUIRED)) {
    const source = read(`model/tla/${model}.tla`)
    const config = read(`model/tla/${model}.cfg`)
    assert.deepEqual(missing(source, config, expected), [], `${model}: a documented invariant is missing`)
    assert.match(script, new RegExp(`^${RUNNER[model]} ${model} pass$`, 'm'), `${model}: baseline run is in CI`)
  }
})

test('the coverage check detects an invariant removed from cfg, model, or both', () => {
  const source = 'TypeOK == TRUE\nOneKeyPerAgent == TRUE\n'
  const cfg = 'SPECIFICATION Spec\nINVARIANTS TypeOK OneKeyPerAgent\n'
  const names = ['TypeOK', 'OneKeyPerAgent']
  assert.deepEqual(missing(source, cfg, names), [])
  assert.deepEqual(missing(source, cfg.replace(' OneKeyPerAgent', ''), names), ['OneKeyPerAgent'])
  assert.deepEqual(missing(source.replace('OneKeyPerAgent == TRUE\n', ''), cfg, names), ['OneKeyPerAgent'])
  assert.deepEqual(missing(source.replace('OneKeyPerAgent == TRUE\n', ''), cfg.replace(' OneKeyPerAgent', ''), names),
    ['OneKeyPerAgent'])
})
