// A deterministic host for the actual id/page.js module. No application source is
// rewritten. Only the browser boundary is simulated; this is not a DOM/WebAuthn
// implementation. See README.md in this directory for its assumptions.
import assert from 'node:assert/strict'
import { AsyncLocalStorage } from 'node:async_hooks'
import { readFile } from 'node:fs/promises'
import { createContext, SourceTextModule, SyntheticModule } from 'node:vm'
import { p256 } from '@noble/curves/nist.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { records, dir } from '../id/impl.mjs'
import { authData, clientData, signOver, sha256 } from '../assertion/helpers.mjs'
import { checkRoot } from '../../src/root.js'
import { checkDelegation } from '../../src/delegation.js'
import { open, wrap } from '../../src/envelope.js'

export const ORIGIN = 'https://id.example'
export const RP = 'id.example'
export const START = 1_800_000_000
export const WORKERS = 'muid.workers'
const ROOT = 'muid.root'
const hex = b => Buffer.from(b).toString('hex')
const secret = sha256('browser-history root')
const spki = s => Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), p256.getPublicKey(s, false)])
export const root = { ...records.rootRecord(spki(secret), -7, RP), credential: 'AAAA', joining: false, registered: true }
export const otherRoot = records.rootRecord(spki(sha256('browser-history joining root')), -7, RP)
const witnessKey = hex(ed25519.getPublicKey(sha256('browser-history witness')))
export const workerSecret = n => sha256(`browser-history worker ${n}`)
export const worker = (n, over = {}) => ({ agent: n === 3 ? 'beta' : 'alpha',
  subject: hex(ed25519.getPublicKey(workerSecret(n))), aud: 'https://app.example', scopes: ['post'], lifetime: 3600, ...over })
export const initialWorkers = () => [worker(1), worker(3)]

const local = new AsyncLocalStorage()
const PUBLISH = new Set(['review-panel', 'renew-panel', 'add-panel', 'handoff', 'renew-handoffs', 'add-handoff'])
const pageText = readFile(new URL('page.js', dir), 'utf8')
const htmlText = readFile(new URL('index.html', dir), 'utf8')
const compiled = new Map()

class Element {
  constructor(world, tab, tag, id = '', hidden = false) {
    this.world = world; this.tab = tab; this.tagName = tag.toLowerCase(); this.id = id
    this.children = []; this.listeners = new Map(); this.value = ''; this.checked = false
    this._hidden = hidden; this._text = ''
  }
  get hidden() { return this._hidden }
  set hidden(value) {
    this._hidden = value
    if (value === false && PUBLISH.has(this.id)) this.world.observe('publish', this.tab, { element: this })
  }
  get textContent() { return this._text + this.children.map(x => x instanceof Element ? x.textContent : String(x)).join('') }
  set textContent(value) {
    this._text = String(value); this.children = []
    if (this.id === 'error' && this._text !== '') this.world.observe('error', this.tab, { message: this._text })
  }
  addEventListener(name, handler) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(handler) }
  append(...children) { this.children.push(...children) }
  replaceChildren(...children) { this.children = children; this._text = '' }
  setAttribute(name, value) { this[name] = String(value) }
  querySelectorAll(tag) { return this.children.filter(x => x instanceof Element).flatMap(x => [...(x.tagName === tag ? [x] : []), ...x.querySelectorAll(tag)]) }
  fire(name) {
    for (const handler of this.listeners.get(name) ?? []) {
      try { Promise.resolve(handler({ target: this })).catch(e => this.world.errors.push(e)) } catch (e) { this.world.errors.push(e) }
    }
  }
}

export class Host {
  constructor({ failWrite = false, now = START, source } = {}) {
    this.now = now; this.source = source; this.failWrite = failWrite
    this.values = new Map([[ROOT, JSON.stringify(root)], [WORKERS, JSON.stringify(initialWorkers())]])
    this.tabs = []; this.requests = []; this.notifications = []; this.errors = []; this.effects = []
    this.operation = 0; this.listener = () => {}
    this.witnessRecords = { roots: [root.text], memberships: [], contests: [], freezes: [], anchors: [], settlements: [] }
  }
  observe(type, tab, detail) {
    const effect = { type, tab, operation: local.getStore(), ...detail }
    this.effects.push(effect); this.listener(effect)
  }
  async drain() {
    // All asynchronous external effects are held in requests/notifications. One
    // event-loop turn drains the native promise jobs without a wall-clock sleep.
    await new Promise(resolve => setImmediate(resolve))
    assert.deepEqual(this.errors, [], 'an unhandled page error is a harness failure')
  }
  request(tab, kind, detail) {
    const operation = local.getStore()
    if (kind === 'signature' && this.requests.some(r => r.tab === tab && r.kind === kind && !r.done)) {
      return Promise.reject(Object.assign(new Error('another authenticator request is pending'), { name: 'NotAllowedError' }))
    }
    return new Promise((resolve, reject) => this.requests.push({ tab, kind, operation, detail, resolve, reject, done: false }))
  }
  async resolve(tab, kind, outcome = 'ok', last = false) {
    const waiting = this.requests.filter(r => !r.done && r.tab === tab && r.kind === kind)
    const r = last ? waiting.at(-1) : waiting[0]
    if (!r) return false
    r.done = true
    if (outcome === 'error') r.reject(new Error(`test ${kind} failure`))
    else if (kind === 'witness') r.resolve({ ok: true, json: async () => this.witnessRecords })
    else if (kind === 'post') r.resolve({ json: async () => ({ ok: true }) })
    else if (kind === 'signature') {
      const { publicKey } = r.detail
      assert.equal(publicKey.userVerification, 'required')
      assert.equal(records.b64u(publicKey.allowCredentials[0].id), root.credential)
      const ad = authData({ rpId: RP, flags: 5, count: ++tab.signatures })
      const cd = Buffer.from(clientData({ challenge: Buffer.from(publicKey.challenge).toString('base64url'), origin: ORIGIN }))
      r.resolve({ response: { authenticatorData: ad, clientDataJSON: cd, signature: signOver(ad, cd, secret) } })
    } else throw new Error(`unhandled effect: ${kind}`)
    await this.drain(); return true
  }
  async deliver(index) {
    // FIFO for each receiving document, as required by the storage task source.
    const at = this.notifications.findIndex(e => e.tab === this.tabs[index] && e.tab.alive)
    if (at < 0) return false
    const e = this.notifications.splice(at, 1)[0]
    this.dispatch(e.tab, 'storage', () => e.tab.storage(e.event), { invalidate: true })
    await this.drain(); return true
  }
  dispatch(tab, kind, action, { invalidate = false, ...detail } = {}) {
    if (invalidate) { tab.generation++; tab.review = null }
    const operation = { id: ++this.operation, tab, kind, generation: tab.generation, ...detail }
    local.run(operation, action)
    return operation
  }
  async open(index) {
    const previous = this.tabs[index]
    if (previous) {
      previous.alive = false
      // A destroyed document cannot resume its callbacks in the new document.
      for (const r of this.requests) if (r.tab === previous) r.done = true
      this.notifications = this.notifications.filter(e => e.tab !== previous)
    }
    const tab = { index, alive: true, generation: 0, review: null, signatures: 0, unticked: new Set(), storage() {} }
    this.tabs[index] = tab
    const html = await htmlText
    const elements = new Map()
    for (const [, tag, attrs, id] of html.matchAll(/<(\w+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
      const e = new Element(this, tab, tag, id, /\bhidden(?:\s|>|$)/.test(attrs))
      e.value = attrs.match(/\bvalue="([^"]*)"/)?.[1] ?? ''
      elements.set(id, e)
    }
    tab.$ = id => { assert.ok(elements.has(id), `unknown element: ${id}`); return elements.get(id) }
    tab.$('agent').value = 'alpha'; tab.$('subject').value = worker(2).subject
    tab.$('aud').value = 'https://app.example'; tab.$('scopes').value = 'post'; tab.$('days').value = String(1 / 24)
    tab.$('new-root').value = otherRoot.text
    const metas = { 'muid-rp-id': RP, 'muid-origin': ORIGIN, 'muid-witness': ORIGIN + '/witness/',
      'muid-witness-keys': JSON.stringify([{ key: witnessKey, nbf: 0, exp: 4_000_000_000 }]) }
    const window = { addEventListener(name, handler) { assert.equal(name, 'storage'); tab.storage = handler } }
    window.top = window.self = window
    const host = this
    const context = createContext({
      window, location: { origin: ORIGIN },
      document: { getElementById: tab.$, createElement: tag => new Element(host, tab, tag),
        querySelector: selector => { const name = selector.match(/^meta\[name="([^"]+)"\]$/)?.[1]; assert.ok(name in metas); return { content: metas[name] } } },
      localStorage: {
        getItem: key => {
          const value = this.values.get(key) ?? null
          // A deterministic cross-agent interleaving: this read linearizes,
          // another document acts, then this caller continues with its result.
          if (this.afterRead?.tab === index && this.afterRead.key === key) {
            const hook = this.afterRead; this.afterRead = null; hook.run()
          }
          return value
        },
        setItem: (key, value) => {
          if (this.failWrite) { this.failWrite = false; throw Object.assign(new Error('test storage failure'), { name: 'QuotaExceededError' }) }
          const oldValue = this.values.get(key) ?? null
          this.values.set(key, value)
          this.observe('write', tab, { key, value })
          if (oldValue !== value) for (const other of this.tabs) if (other && other !== tab && other.alive) {
            this.notifications.push({ tab: other, event: { key, oldValue, newValue: value } })
          }
        },
      },
      navigator: { credentials: { get: options => this.request(tab, 'signature', options) } },
      fetch: (url, options = {}) => this.request(tab, options.method === 'POST' ? 'post' : 'witness', { url, ...options }),
      Date: class extends Date {
        constructor(...args) { super(...(args.length ? args : [host.now * 1000])) }
        static now() { return host.now * 1000 }
      },
    })
    const source = this.source ?? await pageText
    const module = new SourceTextModule(source, { context, identifier: new URL('page.js', dir).href, cachedData: compiled.get(source) })
    await module.link(async specifier => {
      assert.equal(specifier, './records.js', 'new browser dependencies need explicit host adapters')
      return new SyntheticModule(Object.keys(records), function () { for (const [name, value] of Object.entries(records)) this.setExport(name, value) }, { context })
    })
    if (!compiled.has(source)) compiled.set(source, module.createCachedData())
    await module.evaluate(); await this.drain()
    return tab
  }
  async click(index, id, kind, detail = {}, invalidate = false) {
    const tab = this.tabs[index]
    const op = this.dispatch(tab, kind, () => tab.$(id).fire('click'), { ...detail, invalidate })
    await this.drain(); return op
  }
  async edit(index, field, value) {
    const tab = this.tabs[index]
    this.dispatch(tab, 'edit', () => { tab.$(field).value = value; tab.$(field).fire('input') }, { invalidate: true })
    await this.drain()
  }
  forgetNow(index, row) {
    const tab = this.tabs[index]; const li = tab.$('workers').children[row]
    if (!li) return false
    const label = li.textContent.match(/^ ([a-z][a-z0-9_.:-]*) at ([^: ]+(?::\/\/)[^: ]+(?::\d+)?):/)
    assert.ok(label, `cannot read worker row: ${li.textContent}`)
    this.dispatch(tab, 'forget', () => li.querySelectorAll('button')[0].fire('click'), { invalidate: true, agent: label[1], aud: label[2] })
    return true
  }
  async forget(index, row) {
    const happened = this.forgetNow(index, row)
    await this.drain(); return happened
  }
  rows(tab) {
    return tab.$('workers').children.map(li => {
      const m = li.textContent.match(/^ ([a-z][a-z0-9_.:-]*) at (https:\/\/[^ ]+): (.*?) ([0-9a-f]{64})Forget$/)
      assert.ok(m, `cannot read worker row: ${li.textContent}`)
      return { agent: m[1], aud: m[2], scopes: m[3].trim().split(/\s+/), subject: m[4], box: li.querySelectorAll('input')[0] }
    })
  }
  async select(index, row, checked) {
    const tab = this.tabs[index]; const w = this.rows(tab)[row]
    if (!w) return false
    if (w.box.checked === checked) return false
    const slot = JSON.stringify([w.agent, w.aud])
    if (checked) tab.unticked.delete(slot); else tab.unticked.add(slot)
    this.dispatch(tab, 'selection', () => { w.box.checked = checked; w.box.fire('change') }, { invalidate: true })
    await this.drain(); return true
  }
  decode(handoff) {
    const h = typeof handoff === 'string' ? JSON.parse(handoff) : handoff
    return { handoff: h, ...open(wrap(h.payload, { root: h.root, subject: '0'.repeat(128) }), 'delegation') }
  }
  verify(handoff) {
    const d = this.decode(handoff)
    const n = [1, 2, 3].find(n => worker(n).subject === d.body.subject)
    assert.ok(n, 'a handoff names a key outside the test universe')
    const consent = hex(ed25519.sign(Buffer.concat([Buffer.from('muid/v1/accept\n'), Buffer.from(d.id, 'hex')]), workerSecret(n)))
    return checkDelegation(wrap(d.payload, { root: d.handoff.root, subject: consent }), {
      rootKey: checkRoot(root.text, { rpId: RP }).key, rpId: RP, origin: ORIGIN, now: this.now, skew: 60, maxLifetime: 604800,
    })
  }
}
