// SPEC §12: the models of the id page (model/tla/IdPage.tla, IdRoot.tla) and of the witness service's outbox
// (WitnessOutbox.tla) are tied to the code by their
// faults. Each switch a model turns off as a negative control is one fault; the same fault exists as a broken twin
// of the code (tests/meta/id-twins.test.mjs, witness-twins.test.mjs), which its tests must catch. This guard fails if a switch
// has no control that TLC runs, or names a twin that is not there, so a fault the model knows cannot lose its test.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8')

// model: switch: the twins with that fault
const FAULTS = {
  IdPage: {
    Transactional: ['store-read-then-write'],
    FreshWrite: ['stale-list-written'],
    ForgetExact: ['forget-reaches-new-key'],
    CheckReviewed: ['change-while-signing-kept'],
    CheckChanged: ['renew-change-while-signing-kept'],
    CompareRev: ['list-put-back-unseen'],
    CheckExpiry: ['expired-signed', 'expired-handed-over', 'renew-expired-signed', 'renew-expired-handed-over', 'saved-late-handed-over'],
    GuardReplies: ['late-signature-kept', 'renew-late-signature-kept', 'saved-withdrawn-handed-over', 'renew-read-withdrawn-handed-over'],
    PublishAfterCommit: ['unsaved-handed-over', 'store-reports-before-commit'],
    WithdrawOnChange: ['copy-changes-review-stays', 'any-saving-keeps-review'],
    ViewFromStore: ['unsaved-unsaid'],
  },
  IdRoot: {
    CasRoot: ['root-overwritten'],
    OwnOnly: ['create-loser-registers'],
    MarkSent: ['registration-marks-any-root', 'cosign-marks-any-root'],
  },
  WitnessOutbox: {
    SettleFirst: ['outbox-ignored'],
    AppendOutbox: ['outbox-skipped'],
    StageFirst: ['logged-then-kept'],
    AnswerAfterLogged: ['answered-before-logged'],
    ServeSettled: ['outbox-served', 'kept-before-logged'],
    Serialised: ['unserialised'],
  },
}

test('every switch of these models has a negative control TLC runs and a broken twin the tests catch', () => {
  const script = read('.github/scripts/tlc.sh')
  const twins = read('tests/meta/id-twins.test.mjs') + read('tests/meta/witness-twins.test.mjs')
  const configs = readdirSync(new URL('../../model/tla/', import.meta.url)).filter((f) => f.endsWith('.cfg'))
  for (const [model, faults] of Object.entries(FAULTS)) {
    const tla = read(`model/tla/${model}.tla`)
    const declared = tla.slice(tla.indexOf('CONSTANTS'), tla.indexOf('\n\n', tla.indexOf('CONSTANTS')))
    const switches = [...declared.matchAll(/^\s+([A-Z][A-Za-z]+),?\s+\\\*/gm)].map((m) => m[1]).filter((s) => !/^Max|^Tabs$|^InitRows$|^Procs$/.test(s))
    assert.deepEqual(switches.sort(), Object.keys(faults).sort(), `${model}: the switches declared are the faults listed here`)
    for (const [name, list] of Object.entries(faults)) {
      const off = configs.filter((f) => f.startsWith(model) && new RegExp(`^\\s*${name} = FALSE$`, 'm').test(read(`model/tla/${f}`)))
      assert.ok(off.length > 0, `${model}: ${name} is turned off by a configuration`)
      for (const f of off) assert.match(script, new RegExp(`^\\S+ ${f.slice(0, -4)} (?!pass)\\w+$`, 'm'), `${f} is run as a negative control`)
      assert.ok(list.length > 0, `${name} has a twin`)
      for (const twin of list) assert.ok(twins.includes(`\n  ['${twin}', `), `${name}: twin ${twin} exists`)
    }
  }
  // Every configuration of these models is run by the script, in one of its modes, and the workflows run each mode.
  for (const f of configs.filter((f) => /^(Id(Page|Root)|WitnessOutbox)/.test(f))) {
    assert.match(script, new RegExp(`^\\S+ ${f.slice(0, -4)} \\w+$`, 'm'), `${f} is run`)
  }
  const workflows = read('.github/workflows/scan.yml') + read('.github/workflows/model.yml')
  for (const run of ['tlc.sh\n', 'tlc.sh long\n', 'tlc.sh sample "$SECONDS_EACH"\n']) assert.ok(workflows.includes(`run: bash .github/scripts/${run}`), `a workflow runs ${run.trim()}`)
})
