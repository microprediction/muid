// A process of its own for H1's tests of the durable holdings: what one process leaves when it is killed, and what a
// second process meets while the first holds the file. Run as: node holdings-child.mjs <file> <mode>.
import { witnessService, memoryLog, sqliteHoldings } from './impl.mjs'
import { w, IDENTITY, BASE, mBody, signed, rootText } from './fixtures.mjs'

const [, , file, mode] = process.argv
const die = () => process.kill(process.pid, 'SIGKILL')
const say = (line) => new Promise((resolve) => process.stdout.write(line + '\n', resolve))

let holdings
try {
  holdings = sqliteHoldings(file)
} catch (e) {
  await say('refused: ' + e.message)
  process.exit(0)
}
const submit = (svc, type, text) => svc.handle(new Request('https://witness.example/v1/records', { method: 'POST', body: JSON.stringify({ identity: IDENTITY, type, text }) }))

if (mode === 'hold') {
  await say('holding')
  setInterval(() => {}, 1000)
} else if (mode === 'die-inside-update') {
  // The root is kept; the membership's update is entered, and the process dies before it ends.
  const svc = witnessService({ witness: w, holdings, log: memoryLog(), clock: () => BASE, headInterval: 60 })
  await submit(svc, 'root', rootText('a'))
  await say('kept root')
  await holdings.update(IDENTITY, async (entry) => {
    const r = w.admit(entry.held, 'membership', signed('membership', mBody(2, ['a'], IDENTITY), 'a'))
    if (!r.ok) throw new Error('fixture')
    die()
    await new Promise(() => {})
    return { entry: { held: r.held } }
  })
} else if (mode === 'die-in-log') {
  // The anchor is signed and kept in the outbox; the process dies while the log is asked to take it.
  const svc = witnessService({ witness: w, holdings, log: { append: async () => { die(); await new Promise(() => {}) } }, clock: () => BASE, headInterval: 60 })
  await submit(svc, 'membership', signed('membership', mBody(2, ['a'], IDENTITY), 'a'))
} else {
  await say('opened')
  holdings.close()
}
