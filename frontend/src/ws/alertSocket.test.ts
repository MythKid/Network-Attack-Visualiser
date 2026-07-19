import { beforeEach, describe, expect, it } from 'vitest'

import { WS_BACKOFF_BASE_MS, WS_CONNECT_TIMEOUT_MS, WS_FAILURE_CAP } from '../config.ts'
import {
  AlertSocket,
  computeBackoffDelay,
  type SocketCloseInfo,
  type SocketMeta,
  type SocketPhase,
  type WebSocketLike,
} from './alertSocket.ts'

class FakeSocket implements WebSocketLike {
  onopen: (() => void) | null = null
  onmessage: ((event: { data: unknown }) => void) | null = null
  onerror: (() => void) | null = null
  onclose: ((event: SocketCloseInfo) => void) | null = null
  closed = false
  closeCalls = 0

  close(): void {
    this.closed = true
    this.closeCalls += 1
  }

  emitOpen(): void {
    this.onopen?.()
  }
  emitMessage(data: unknown): void {
    this.onmessage?.({ data })
  }
  emitError(): void {
    this.onerror?.()
  }
  emitClose(code: number, reason = ''): void {
    this.onclose?.({ code, reason })
  }
}

interface Scheduled {
  id: number
  cb: () => void
  at: number
}

class FakeScheduler {
  time = 0
  private seq = 0
  scheduled: Scheduled[] = []

  setTimer = (cb: () => void, ms: number): number => {
    const id = ++this.seq
    this.scheduled.push({ id, cb, at: this.time + ms })
    return id
  }

  clearTimer = (id: number): void => {
    this.scheduled = this.scheduled.filter((s) => s.id !== id)
  }

  advance(ms: number): void {
    this.time += ms
    const due = this.scheduled.filter((s) => s.at <= this.time).sort((a, b) => a.at - b.at)
    this.scheduled = this.scheduled.filter((s) => s.at > this.time)
    for (const timer of due) timer.cb()
  }

  get pendingCount(): number {
    return this.scheduled.length
  }
}

interface Harness {
  socket: AlertSocket
  sockets: FakeSocket[]
  scheduler: FakeScheduler
  states: { phase: SocketPhase; meta: SocketMeta }[]
  frames: string[]
  last: () => FakeSocket
}

function makeHarness(random = 0.5): Harness {
  const sockets: FakeSocket[] = []
  const scheduler = new FakeScheduler()
  const states: { phase: SocketPhase; meta: SocketMeta }[] = []
  const frames: string[] = []
  const socket = new AlertSocket({
    url: 'ws://localhost:8000/api/v1/ws/alerts',
    onFrame: (data) => frames.push(data),
    onState: (phase, meta) => states.push({ phase, meta: { ...meta } }),
    deps: {
      createSocket: () => {
        const s = new FakeSocket()
        sockets.push(s)
        return s
      },
      setTimer: scheduler.setTimer,
      clearTimer: scheduler.clearTimer,
      random: () => random,
    },
  })
  return { socket, sockets, scheduler, states, frames, last: () => sockets[sockets.length - 1] }
}

function phases(h: Harness): SocketPhase[] {
  return h.states.map((s) => s.phase)
}

describe('AlertSocket lifecycle', () => {
  let h: Harness
  beforeEach(() => {
    h = makeHarness()
  })

  it('connects and forwards only string frames', () => {
    h.socket.start()
    h.last().emitOpen()
    h.last().emitMessage('{"type":"alert.created"}')
    h.last().emitMessage({ not: 'a string' })
    expect(phases(h)).toEqual(['connecting', 'connected'])
    expect(h.frames).toEqual(['{"type":"alert.created"}'])
  })

  it('onerror records diagnostics only: the paired close owns the single reconnect', () => {
    h.socket.start()
    h.last().emitError()
    expect(h.scheduler.pendingCount).toBe(1) // only the connect timeout, no reconnect
    h.last().emitClose(1006)
    expect(phases(h)).toContain('reconnecting')
    expect(h.states.at(-1)?.meta.failureCount).toBe(1)
    // exactly one reconnect timer pending (connect timeout was cleared on close)
    expect(h.scheduler.pendingCount).toBe(1)
  })

  it('connect timeout finalizes, closes the socket and schedules its own reconnect', () => {
    h.socket.start()
    const stale = h.last()
    h.scheduler.advance(WS_CONNECT_TIMEOUT_MS)
    expect(stale.closed).toBe(true)
    expect(phases(h)).toEqual(['connecting', 'reconnecting'])
    // A late open from the finalized/stale socket does nothing.
    stale.emitOpen()
    expect(phases(h)).not.toContain('connected')
  })

  it('recovers from a remote normal close (code 1000)', () => {
    h.socket.start()
    h.last().emitOpen()
    h.last().emitClose(1000)
    expect(h.states.at(-1)?.phase).toBe('reconnecting')
  })

  it('treats an explicit 1008 as a terminal configuration error (no reconnect)', () => {
    h.socket.start()
    h.last().emitClose(1008)
    expect(h.states.at(-1)?.phase).toBe('config_error')
    expect(h.scheduler.pendingCount).toBe(0)
  })

  it('ignores stale-attempt events after reconnection', () => {
    h.socket.start()
    const first = h.last()
    first.emitClose(1006)
    h.scheduler.advance(WS_BACKOFF_BASE_MS) // reconnect timer fires -> second attempt
    const second = h.last()
    expect(second).not.toBe(first)
    // Stale first socket emits after being superseded: no effect.
    first.emitMessage('stale')
    first.emitClose(1000)
    expect(h.frames).toEqual([])
    expect(second.closed).toBe(false)
  })

  it('manual retry cancels a pending reconnect timer and starts exactly one replacement', () => {
    h.socket.start()
    h.last().emitClose(1006) // -> reconnecting, one pending timer
    const socketsBefore = h.sockets.length
    h.socket.retryNow()
    expect(h.sockets.length).toBe(socketsBefore + 1) // exactly one replacement
    expect(h.states.at(-1)?.phase).toBe('connecting')
    expect(h.states.at(-1)?.meta.failureCount).toBe(0) // reset on manual retry
    // The old pending reconnect timer was cleared: advancing does not open again.
    const socketsAfter = h.sockets.length
    h.scheduler.advance(60_000)
    expect(h.sockets.length).toBe(socketsAfter)
  })

  it('a successful open resets the failure counter and backoff', () => {
    h.socket.start()
    h.last().emitClose(1006) // failureCount 1
    h.scheduler.advance(WS_BACKOFF_BASE_MS)
    h.last().emitOpen() // reset to 0
    h.last().emitClose(1006) // failureCount back to 1 -> base backoff again
    expect(h.states.at(-1)?.meta.failureCount).toBe(1)
  })

  it('stops auto-retrying after the failure cap and recovers on manual retry', () => {
    const advancePastBackoff = 60_000
    h.socket.start()
    for (let i = 0; i < WS_FAILURE_CAP; i += 1) {
      h.last().emitClose(1006)
      if (h.states.at(-1)?.phase === 'reconnecting') {
        h.scheduler.advance(advancePastBackoff)
      }
    }
    expect(h.states.at(-1)?.phase).toBe('capped')
    expect(h.scheduler.pendingCount).toBe(0)
    h.socket.retryNow()
    expect(h.states.at(-1)?.phase).toBe('connecting')
    expect(h.states.at(-1)?.meta.failureCount).toBe(0)
  })

  it('dispose closes the live socket, clears timers and ignores later events', () => {
    h.socket.start()
    const live = h.last()
    h.socket.dispose()
    expect(live.closed).toBe(true)
    expect(h.scheduler.pendingCount).toBe(0)
    expect(h.states.at(-1)?.phase).toBe('disposed')
    // Late events from the disposed attempt do nothing.
    live.emitOpen()
    live.emitClose(1006)
    expect(phases(h)).not.toContain('connected')
    expect(h.scheduler.pendingCount).toBe(0)
  })
})

describe('computeBackoffDelay', () => {
  it('returns the base delay for the first failure (no jitter at random=0.5)', () => {
    expect(computeBackoffDelay(1, 0.5)).toBe(WS_BACKOFF_BASE_MS)
  })

  it('doubles with each consecutive failure', () => {
    expect(computeBackoffDelay(2, 0.5)).toBe(WS_BACKOFF_BASE_MS * 2)
    expect(computeBackoffDelay(3, 0.5)).toBe(WS_BACKOFF_BASE_MS * 4)
  })

  it('applies symmetric jitter', () => {
    expect(computeBackoffDelay(1, 0)).toBeLessThan(WS_BACKOFF_BASE_MS)
    expect(computeBackoffDelay(1, 1)).toBeGreaterThan(WS_BACKOFF_BASE_MS)
  })

  it('is capped at the maximum backoff', () => {
    expect(computeBackoffDelay(50, 0.5)).toBeLessThanOrEqual(30000)
  })
})
