// A suite a harness runs in a process of its own, and ends with every process it started, browsers included. A
// browser is not in the suite's process group (Playwright starts it in its own), and a process killed outright
// cannot close what it started: so what is ended is the process tree, found by parent, as tree-kill finds it. Each
// round stops what it finds (SIGSTOP: nothing stopped starts anything more) and looks again, until nothing new is
// found; then all of it is killed. Whatever the harness still runs when it exits, or is told to stop, is ended too.
import { spawn, execFileSync } from 'node:child_process'

const live = new Set()

function children () {
  const of = new Map()
  for (const line of execFileSync('ps', ['-A', '-o', 'pid=,ppid='], { encoding: 'utf8' }).split('\n')) {
    const [pid, ppid] = line.trim().split(/\s+/).map(Number)
    if (!Number.isInteger(pid) || !Number.isInteger(ppid)) continue
    if (!of.has(ppid)) of.set(ppid, [])
    of.get(ppid).push(pid)
  }
  return of
}

const signal = (pid, s) => { try { process.kill(pid, s) } catch { /* already gone */ } }

// Ends `child` and everything it started, as far as it is still running.
export function end (child) {
  if (child.exitCode !== null || child.signalCode !== null) return
  const found = new Set()
  for (let more = true; more;) {
    more = false
    const of = children()
    for (const queue = [child.pid]; queue.length > 0;) {
      const pid = queue.pop()
      if (!found.has(pid)) { found.add(pid); more = true; signal(pid, 'SIGSTOP') }
      queue.push(...(of.get(pid) ?? []))
    }
  }
  for (const pid of found) signal(pid, 'SIGKILL')
}

// `node` with `args`, as spawn would start it, in a process group of its own.
export function start (args, options) {
  const child = spawn(process.execPath, args, { ...options, detached: true })
  live.add(child)
  child.on('close', () => live.delete(child))
  return child
}

process.on('exit', () => { for (const child of live) end(child) })
for (const s of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.once(s, () => {
    for (const child of live) end(child)
    process.kill(process.pid, s) // as told, now that nothing is left behind
  })
}
