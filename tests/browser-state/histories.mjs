// Independent intent/history oracle. In particular it never calls remember(),
// storedWorkers() or renewals() to decide what a successful storage write means.
import assert from 'node:assert/strict'
import { Host, WORKERS, initialWorkers, worker, otherRoot } from './harness.mjs'

const plain = x => JSON.parse(JSON.stringify(x))
const ordered = list => plain(list).sort((a, b) => JSON.stringify([a.agent, a.aud]).localeCompare(JSON.stringify([b.agent, b.aud])))
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b)
const families = { worker: ['review', 'sign'], renewal: ['renew-review', 'renew-sign'], add: ['add-review', 'add-sign'] }

export class History {
  constructor(options) {
    this.host = new Host(options); this.expected = initialWorkers(); this.failures = []; this.trace = []; this.publications = []
    this.host.listener = e => this.observe(e)
  }
  async open() { await this.host.open(0); await this.host.open(1); return this }
  fail(contract, message) { this.failures.push({ contract, message, trace: [...this.trace] }) }
  observe(e) {
    const op = e.operation
    if (e.type === 'write' && e.key === WORKERS) {
      let next
      if (op?.kind === 'sign-worker' && op.review?.entered) {
        const w = op.review.entered
        // An agent has a current key plus one grant per audience. A new key
        // starts a new set of grants. This is the abstract user operation.
        const agents = new Map()
        for (const x of this.expected) {
          if (!agents.has(x.agent)) agents.set(x.agent, { key: x.subject, grants: new Map() })
          agents.get(x.agent).grants.set(x.aud, x)
        }
        if (agents.get(w.agent)?.key !== w.subject) agents.set(w.agent, { key: w.subject, grants: new Map() })
        agents.get(w.agent).grants.set(w.aud, w)
        next = [...agents.values()].flatMap(a => [...a.grants.values()])
        op.committed = true
      } else if (op?.kind === 'forget') next = this.expected.filter(w => w.agent !== op.agent || w.aud !== op.aud)
      else { this.fail('unexplained-write', `workers written by ${op?.kind ?? 'an untracked callback'}`); return }
      const actual = JSON.parse(e.value)
      if (!equal(ordered(actual), ordered(next))) this.fail('storage-history', 'a write disagrees with the committed authorization/Forget history')
      if (op.generation !== op.tab.generation) this.fail('cancelled-write', 'a withdrawn operation changed persisted workers')
      this.expected = next
    }
    if (e.type === 'error' && op && op.generation !== op.tab.generation) this.fail('late-error', 'an error from a withdrawn operation overwrote the current UI')
    if (e.type === 'publish') this.publications.push(e)
  }
  check() {
    for (const tab of this.host.tabs) {
      const rows = this.host.rows(tab); const listed = new Set(rows.map(w => JSON.stringify([w.agent, w.aud])))
      for (const slot of tab.unticked) if (!listed.has(slot)) tab.unticked.delete(slot)
      for (const w of rows) if (w.box.checked === tab.unticked.has(JSON.stringify([w.agent, w.aud]))) {
        this.fail('selection', 'a listed worker disagrees with the user selection retained for that entry')
      }
    }
    for (const e of this.publications.splice(0)) {
      const { operation: op, tab, element } = e
      if (element.hidden) continue
      if (!op || op.generation !== tab.generation) {
        this.fail(element.id.endsWith('panel') ? 'review-cancellation' : 'handoff-cancellation', `${element.id} was restored by a withdrawn callback`)
        continue
      }
      if (element.id === 'handoff' || element.id === 'renew-handoffs') {
        if (element.id === 'handoff' && !op.committed) this.fail('persistence', 'a replacement handoff was published without committing its remembered key')
        const handoffs = element.id === 'handoff' ? [element.value] : element.children.map(x => x.value)
        if (element.id === 'renew-handoffs' && op.review?.selected) {
          const actual = handoffs.map(h => {
            const b = this.host.decode(h).body
            return { agent: b.agent, aud: b.aud, scopes: plain(b.scopes), subject: b.subject }
          })
          if (!equal(actual, op.review.selected)) this.fail('review-payload', 'the renewed batch differs from the selection at Review')
        }
        for (const h of handoffs) {
          const d = this.host.decode(h)
          const verdict = this.host.verify(h)
          if (!verdict.ok) this.fail(d.body.exp <= this.host.now ? 'expired-handoff' : 'invalid-handoff', `a published handoff is refused by the core: ${verdict.reason}`)
          if (op.kind === 'sign-renewal' && !this.expected.some(w => w.agent === d.body.agent && w.subject === d.body.subject && w.aud === d.body.aud)) {
            this.fail('retired-renewal', 'a renewal names a key or grant absent from the current committed authorization history')
          }
          if (op.kind === 'sign-worker' && op.review?.entered) {
            const wanted = op.review.entered
            for (const field of ['agent', 'subject', 'aud']) if (d.body[field] !== wanted[field]) this.fail('review-payload', `signed ${field} differs from the Review input snapshot`)
            if (!equal(plain(d.body.scopes), wanted.scopes)) this.fail('review-payload', 'signed scopes differ from the Review input snapshot')
          }
        }
      }
    }
  }
  async step(action) {
    const { tab: index = 0, type, family = 'worker' } = action
    const host = this.host; const tab = host.tabs[index]
    this.trace.push(action)
    if (type === 'review') {
      const entered = { agent: tab.$('agent').value.trim(), subject: tab.$('subject').value.trim(), aud: tab.$('aud').value.trim(),
        scopes: [...new Set(tab.$('scopes').value.trim().split(/\s+/))].sort(), lifetime: Math.round(Number(tab.$('days').value) * 86400) }
      const selected = host.rows(tab).filter(w => !tab.unticked.has(JSON.stringify([w.agent, w.aud])))
        .map(({ agent, aud, scopes, subject }) => ({ agent, aud, scopes, subject }))
      const op = await host.click(index, families[family][0], `review-${family}`, { entered, selected }, true)
      if (op.generation === tab.generation) tab.review = op
    } else if (type === 'sign') await host.click(index, families[family][1], `sign-${family}`, { review: tab.review })
    else if (type === 'reply') await host.resolve(tab, action.kind, action.outcome, action.last)
    else if (type === 'forget') await host.forget(index, action.row)
    else if (type === 'select') await host.select(index, action.row, action.checked)
    else if (type === 'edit') await host.edit(index, action.field, action.value)
    else if (type === 'reload') await host.open(index)
    else if (type === 'deliver') await host.deliver(index)
    else if (type === 'fail-write') host.failWrite = true
    else if (type === 'advance') host.now += action.seconds
    else throw new Error(`unknown command: ${type}`)
    this.check()
  }
}

// These are available user workflows and independent environment actions, not
// bug-specific traces. All order-preserving pairwise interleavings are explored.
export function operations(tab = 0) {
  const grant = family => [
    { type: 'review', family, tab }, { type: 'reply', kind: 'witness', tab },
    { type: 'sign', family, tab }, { type: 'reply', kind: 'signature', tab },
    ...(family === 'add' ? [{ type: 'reply', kind: 'post', tab }, { type: 'reply', kind: 'post', tab }] : []),
  ]
  return {
    authorise: grant('worker'), renew: grant('renewal'), add: grant('add'),
    forgetFirst: [{ type: 'forget', row: 0, tab }], forgetOther: [{ type: 'forget', row: 1, tab }],
    editKey: [{ type: 'edit', field: 'subject', value: worker(1).subject, tab }],
    editScope: [{ type: 'edit', field: 'scopes', value: 'read', tab }],
    editRoot: [{ type: 'edit', field: 'new-root', value: otherRoot.text + ' ', tab }],
    editAudience: [{ type: 'edit', field: 'aud', value: 'https://other.example', tab }],
    untick: [{ type: 'select', row: 0, checked: false, tab }],
    retick: [{ type: 'select', row: 0, checked: true, tab }],
    reload: [{ type: 'reload', tab }], quota: [{ type: 'fail-write' }],
    tick: [{ type: 'advance', seconds: 7200 }], notify: [{ type: 'deliver', tab }],
    failedReview: [{ type: 'review', family: 'worker', tab }, { type: 'reply', kind: 'witness', outcome: 'error', tab }],
  }
}

export function *interleavings(left, right, prefix = []) {
  if (left.length === 0 && right.length === 0) { yield prefix; return }
  if (left.length) yield *interleavings(left.slice(1), right, [...prefix, left[0]])
  if (right.length) yield *interleavings(left, right.slice(1), [...prefix, right[0]])
}

export async function run(actions, options = {}) {
  const h = await new History(options).open()
  for (const a of actions) {
    await h.step(a)
    // Stop at the first violating transition; subsequent failures could just be
    // consequences of a history that has already left the specification.
    if (h.failures.length) break
  }
  return h
}

export async function explore({ source, limit = Infinity } = {}) {
  const found = new Map(); let histories = 0; let transitions = 0
  const seen = new Set()
  const first = operations(0)
  // A workflow is paired with another workflow or one environment/user action.
  // Same-tab edits and cross-tab mutations are both represented.
  for (const name of ['authorise', 'renew', 'add', 'failedReview']) {
    for (const tab of [0, 1]) for (const [other, actions] of Object.entries(operations(tab))) {
      for (const trace of interleavings(first[name], actions)) {
        // Eight transitions suffice to complete two ordinary authorizations.
        // Deduplicate identical prefixes from symmetric operation pairings.
        const prefix = trace.slice(0, 8)
        const key = JSON.stringify(prefix)
        if (seen.has(key)) continue
        seen.add(key)
        if (histories >= limit) return { found, histories, transitions }
        const h = await run(prefix, { source }); histories++; transitions += h.trace.length
        for (const f of h.failures) {
          const before = found.get(f.contract)
          if (!before || f.trace.length < before.trace.length) found.set(f.contract, { ...f, pair: `${name}/tab0 + ${other}/tab${tab}` })
        }
      }
    }
  }
  assert.ok(histories > 0)
  return { found, histories, transitions }
}
