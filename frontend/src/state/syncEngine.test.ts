import { beforeEach, describe, expect, it } from 'vitest'

import type { AlertQuery } from '../api/client.ts'
import { SYNC_RETRY_DELAY_MS, WS_BUFFER_MAX, WS_CONNECT_TIMEOUT_MS } from '../config.ts'
import { makeAlert } from '../test/factories.ts'
import type { Alert, AlertListResponse } from '../types/alert.ts'
import { DEFAULT_SCOPE, type Scope } from '../types/filters.ts'
import type { AlertEnvelope, AlertEnvelopeType } from '../types/ws.ts'
import type { SocketCloseInfo, WebSocketLike } from '../ws/alertSocket.ts'
import { SyncEngine, type EngineState } from './syncEngine.ts'

// --- fakes -------------------------------------------------------------------

class FakeSocket implements WebSocketLike {
  onopen: (() => void) | null = null
  onmessage: ((event: { data: unknown }) => void) | null = null
  onerror: (() => void) | null = null
  onclose: ((event: SocketCloseInfo) => void) | null = null
  close(): void {}
  emitOpen(): void {
    this.onopen?.()
  }
  emitMessage(data: unknown): void {
    this.onmessage?.({ data })
  }
  emitClose(code: number): void {
    this.onclose?.({ code, reason: '' })
  }
}

class FakeScheduler {
  time = 0
  private seq = 0
  private timers: { id: number; cb: () => void; at: number }[] = []
  setTimer = (cb: () => void, ms: number): number => {
    const id = ++this.seq
    this.timers.push({ id, cb, at: this.time + ms })
    return id
  }
  clearTimer = (id: number): void => {
    this.timers = this.timers.filter((t) => t.id !== id)
  }
  advance(ms: number): void {
    this.time += ms
    const due = this.timers.filter((t) => t.at <= this.time).sort((a, b) => a.at - b.at)
    this.timers = this.timers.filter((t) => t.at > this.time)
    for (const t of due) t.cb()
  }
}

interface PendingFetch {
  query: AlertQuery
  resolve: (page: AlertListResponse) => void
  reject: (error: unknown) => void
}

class FakeFetch {
  count = 0
  abortedCount = 0
  private pending: PendingFetch[] = []

  fetch = (query: AlertQuery, signal: AbortSignal): Promise<AlertListResponse> => {
    this.count += 1
    return new Promise<AlertListResponse>((resolve, reject) => {
      const entry: PendingFetch = { query, resolve, reject }
      this.pending.push(entry)
      const onAbort = () => {
        this.abortedCount += 1
        this.pending = this.pending.filter((e) => e !== entry)
        reject(new DOMException('aborted', 'AbortError'))
      }
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    })
  }

  get pendingCount(): number {
    return this.pending.length
  }

  resolveNext(page: AlertListResponse): void {
    const entry = this.pending.shift()
    if (!entry) throw new Error('no pending fetch to resolve')
    entry.resolve(page)
  }

  rejectNext(error: unknown): void {
    const entry = this.pending.shift()
    if (!entry) throw new Error('no pending fetch to reject')
    entry.reject(error)
  }
}

function page(alerts: Alert[], total = alerts.length): AlertListResponse {
  return { items: alerts, total, limit: 50, offset: 0 }
}

function envelope(type: AlertEnvelopeType, alert: Alert): AlertEnvelope {
  return { type, alert }
}

interface Harness {
  engine: SyncEngine
  fetch: FakeFetch
  scheduler: FakeScheduler
  sockets: FakeSocket[]
  state: () => EngineState
  connect: () => void
  drop: (code?: number) => void
  send: (env: AlertEnvelope) => void
  sendRaw: (data: string) => void
  flush: () => Promise<void>
}

function makeEngine(scope: Scope = DEFAULT_SCOPE): Harness {
  const fetch = new FakeFetch()
  const scheduler = new FakeScheduler()
  const sockets: FakeSocket[] = []
  const engine = new SyncEngine({
    wsUrl: 'ws://localhost:8000/api/v1/ws/alerts',
    scope,
    deps: {
      fetchAlerts: fetch.fetch,
      setTimer: scheduler.setTimer,
      clearTimer: scheduler.clearTimer,
      socketDeps: {
        createSocket: () => {
          const s = new FakeSocket()
          sockets.push(s)
          return s
        },
        setTimer: scheduler.setTimer,
        clearTimer: scheduler.clearTimer,
        random: () => 0.5,
      },
    },
  })
  const last = () => sockets[sockets.length - 1]
  return {
    engine,
    fetch,
    scheduler,
    sockets,
    state: () => engine.getState(),
    connect: () => last().emitOpen(),
    drop: (code = 1006) => last().emitClose(code),
    send: (env) => last().emitMessage(JSON.stringify(env)),
    sendRaw: (data) => last().emitMessage(data),
    flush: async () => {
      for (let i = 0; i < 15; i += 1) await Promise.resolve()
    },
  }
}

// --- tests -------------------------------------------------------------------

describe('SyncEngine — initial sync', () => {
  let h: Harness
  beforeEach(() => {
    h = makeEngine()
  })

  it('loads a snapshot on the connected path', async () => {
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' }), makeAlert({ alert_id: 'b' })]))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['a', 'b'])
    expect(h.state().connection).toBe('connected')
    expect(h.state().freshness).toBe('reconciled')
    expect(h.state().total).toBe(2)
  })

  it('installs REST data offline when the socket never opens (independent dimensions)', async () => {
    h.engine.start()
    h.scheduler.advance(WS_CONNECT_TIMEOUT_MS) // connect times out
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().connection).toBe('offline')
    expect(h.state().freshness).toBe('reconciled')
    expect(h.state().alerts).toHaveLength(1)
  })

  it('shows an error state when the initial snapshot fails, then recovers on retry', async () => {
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.rejectNext(new Error('boom'))
    await h.flush()
    expect(h.state().freshness).toBe('error')
    // bounded retry through the scheduler
    h.scheduler.advance(SYNC_RETRY_DELAY_MS)
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
    expect(h.state().alerts).toHaveLength(1)
  })
})

describe('SyncEngine — buffering and live deltas', () => {
  let h: Harness
  beforeEach(() => {
    h = makeEngine()
  })

  it('buffers a delta that arrives before install and drains it onto the snapshot', async () => {
    h.engine.start()
    h.connect()
    await h.flush()
    // arrives while the snapshot fetch is in flight -> buffered
    h.send(envelope('alert.created', makeAlert({ alert_id: 'buffered' })))
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })]))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['buffered', 'base'])
    expect(h.state().freshness).toBe('pending') // optimistic insert awaits reconcile
  })

  it('applies a live created optimistically and marks the view pending', async () => {
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })]))
    await h.flush()
    h.send(envelope('alert.created', makeAlert({ alert_id: 'live' })))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['live', 'base'])
    expect(h.state().freshness).toBe('pending')
  })

  it('never downgrades a loaded row from a late created', async () => {
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'x', occurrence_count: 3, severity: 'high' })]))
    await h.flush()
    h.send(envelope('alert.created', makeAlert({ alert_id: 'x', occurrence_count: 1, severity: 'low' })))
    await h.flush()
    expect(h.state().alerts[0].occurrence_count).toBe(3)
    expect(h.state().alerts[0].severity).toBe('high')
  })

  it('reconciles (never inserts) for an unknown updated in scope', async () => {
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    const before = h.fetch.count
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'unknown', occurrence_count: 2 })))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['a']) // not inserted
    expect(h.fetch.count).toBe(before + 1) // a reconcile was requested
  })
})

describe('SyncEngine — membership and pruning', () => {
  it('removes a row that escalates out of the active severity filter and reconciles', async () => {
    const scope: Scope = {
      provenance: 'all',
      filters: { severity: 'medium', detector_id: null, category: null },
    }
    const h = makeEngine(scope)
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'x', severity: 'medium', occurrence_count: 1 })]))
    await h.flush()
    // escalates medium -> high: no longer matches the medium filter
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'x', severity: 'high', occurrence_count: 2 })))
    await h.flush()
    expect(h.state().alerts).toHaveLength(0)
    expect(h.state().freshness).toBe('pending')
    // reconciliation backfills the page with another matching row
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'y', severity: 'medium' })], 1))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['y'])
    expect(h.state().freshness).toBe('reconciled')
  })

  it('reconciles on a non-matching created so global pruning removes a matching row', async () => {
    const scope: Scope = {
      provenance: 'synthetic',
      filters: { severity: null, detector_id: null, category: null },
    }
    const h = makeEngine(scope)
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a', source_type: 'synthetic' })]))
    await h.flush()
    // a live-provenance created: not admitted, but still schedules reconciliation
    h.send(envelope('alert.created', makeAlert({ alert_id: 'live1', source_type: 'live' })))
    // fire the created-reconcile debounce
    h.scheduler.advance(300)
    await h.flush()
    // authoritative snapshot no longer contains 'a' (it was pruned globally)
    h.fetch.resolveNext(page([], 0))
    await h.flush()
    expect(h.state().alerts).toHaveLength(0)
    expect(h.state().freshness).toBe('reconciled')
  })
})

describe('SyncEngine — scheduling', () => {
  it('supersedes and aborts the in-flight sync on a scope change', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    expect(h.fetch.pendingCount).toBe(1)
    h.engine.setScope({
      provenance: 'synthetic',
      filters: { severity: null, detector_id: null, category: null },
    })
    await h.flush()
    expect(h.fetch.abortedCount).toBe(1) // previous fetch aborted
    expect(h.state().alerts).toHaveLength(0) // previous page cleared immediately
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'synth', source_type: 'synthetic' })]))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['synth'])
  })

  it('coalesces a burst of invalid frames during a sync into at most one follow-up', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    const before = h.fetch.count
    // trigger a sync, then spam invalid frames while it is in flight
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'unknown', occurrence_count: 2 })))
    await h.flush()
    for (let i = 0; i < 8; i += 1) h.sendRaw('not json {')
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    // exactly one reconcile fetch plus one coalesced follow-up
    expect(h.fetch.count).toBe(before + 2)
  })

  it('fires a created reconcile within the maximum wait despite a continuous stream', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    const before = h.fetch.count
    // continuous created stream: each resets the trailing debounce (200 < 250ms)
    h.send(envelope('alert.created', makeAlert({ alert_id: 'c0' })))
    for (let i = 1; i <= 9; i += 1) {
      h.scheduler.advance(200)
      h.send(envelope('alert.created', makeAlert({ alert_id: `c${i}` })))
    }
    expect(h.fetch.count).toBe(before) // debounce kept being postponed
    h.scheduler.advance(200) // crosses the 2000ms max-wait deadline
    await h.flush()
    expect(h.fetch.count).toBe(before + 1) // deadline forced a reconcile
  })
})

describe('SyncEngine — failure and buffer bounds', () => {
  it('preserves the prior snapshot and goes stale on a refresh failure, then recovers', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    // trigger a reconcile and fail it
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'unknown', occurrence_count: 2 })))
    await h.flush()
    h.fetch.rejectNext(new Error('refresh failed'))
    await h.flush()
    expect(h.state().freshness).toBe('stale')
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['a']) // preserved
    h.scheduler.advance(SYNC_RETRY_DELAY_MS)
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
  })

  it('marks a run overflowed, requires a fresh follow-up, and recovers to reconciled', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    // flood the buffer while the first snapshot fetch is in flight
    for (let i = 0; i <= WS_BUFFER_MAX; i += 1) {
      h.send(envelope('alert.created', makeAlert({ alert_id: `flood-${i}` })))
    }
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })]))
    await h.flush()
    expect(h.state().freshness).toBe('stale') // overflow -> not canonical yet
    // the mandatory follow-up sync runs and reconciles
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
  })
})

describe('SyncEngine — reconnect', () => {
  it('runs a fresh resync and bumps the reconnect nonce when the socket reconnects', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    const nonceBefore = h.state().reconnectNonce
    const countBefore = h.fetch.count
    h.drop(1006) // connection lost
    h.scheduler.advance(60_000) // reconnect backoff timer fires -> new attempt
    h.connect() // the new socket opens
    await h.flush()
    expect(h.state().reconnectNonce).toBe(nonceBefore + 1)
    expect(h.fetch.count).toBe(countBefore + 1) // reconnect triggered a fresh sync
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' }), makeAlert({ alert_id: 'b' })]))
    await h.flush()
    expect(h.state().alerts).toHaveLength(2)
    expect(h.state().connection).toBe('connected')
  })
})

const MEDIUM_SCOPE: Scope = {
  provenance: 'all',
  filters: { severity: 'medium', detector_id: null, category: null },
}

describe('SyncEngine — version-first membership (corrections)', () => {
  it('ignores a stale out-of-scope update and never removes a newer in-scope row', async () => {
    const h = makeEngine(MEDIUM_SCOPE)
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'x', severity: 'medium', occurrence_count: 3 })]))
    await h.flush()
    const before = h.fetch.count
    // stale (occ 2 < 3) AND out-of-scope (high vs medium filter): must be ignored entirely
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'x', severity: 'high', occurrence_count: 2 })))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['x'])
    expect(h.state().alerts[0].occurrence_count).toBe(3)
    expect(h.state().alerts[0].severity).toBe('medium')
    expect(h.fetch.count).toBe(before) // no removal, no reconcile
  })

  it('buffers an escalation-out update during a sync and invalidates the stale snapshot on replay', async () => {
    const h = makeEngine(MEDIUM_SCOPE)
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'x', severity: 'medium', occurrence_count: 1 })]))
    await h.flush()
    // start a reconcile sync
    h.send(envelope('alert.created', makeAlert({ alert_id: 'trigger', severity: 'medium' })))
    h.scheduler.advance(300)
    await h.flush() // reconcile fetch now in flight (buffering)
    // escalation-out update arrives during the sync: high (out of medium filter), occ 2
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'x', severity: 'high', occurrence_count: 2 })))
    // the REST response is STALE: still the medium occ-1 version of x
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'x', severity: 'medium', occurrence_count: 1 })]))
    await h.flush()
    // buffered replay sees occ 2 > 1 and high != medium -> removes x and reconciles
    expect(h.state().alerts.map((a) => a.alert_id)).not.toContain('x')
    expect(h.state().freshness).toBe('pending')
  })
})

describe('SyncEngine — reconciliation-pending lifecycle (corrections)', () => {
  it('reports connected + pending on reconnect until the resync snapshot succeeds', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
    h.drop(1006)
    h.scheduler.advance(60_000)
    h.connect()
    await h.flush()
    expect(h.state().connection).toBe('connected')
    expect(h.state().freshness).toBe('pending')
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
  })

  it('marks freshness pending immediately on a non-matching created', async () => {
    const h = makeEngine({ provenance: 'synthetic', filters: { severity: null, detector_id: null, category: null } })
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a', source_type: 'synthetic' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
    h.send(envelope('alert.created', makeAlert({ alert_id: 'live1', source_type: 'live' })))
    await h.flush()
    expect(h.state().freshness).toBe('pending')
  })

  it('never publishes an intermediate reconciled state before a required follow-up', async () => {
    const h = makeEngine()
    const log: string[] = []
    const unsub = h.engine.subscribe(() => log.push(h.state().freshness))
    h.engine.start()
    h.connect()
    await h.flush()
    // a created during the initial sync forces a follow-up
    h.send(envelope('alert.created', makeAlert({ alert_id: 'c1' })))
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })]))
    await h.flush()
    expect(h.state().freshness).toBe('pending') // follow-up in flight, not reconciled
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' }), makeAlert({ alert_id: 'c1' })]))
    await h.flush()
    unsub()
    expect(h.state().freshness).toBe('reconciled')
    expect(log.filter((f) => f === 'reconciled')).toHaveLength(1) // exactly one, at the end
  })
})

describe('SyncEngine — failure and retry scheduling (corrections)', () => {
  it('does not retry-loop when a created arrives during a failed sync', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'ghost', occurrence_count: 2 })))
    await h.flush()
    const atFailure = h.fetch.count // reconcile fetch is in flight
    h.send(envelope('alert.created', makeAlert({ alert_id: 'c' }))) // buffered
    h.fetch.rejectNext(new Error('boom'))
    await h.flush()
    expect(h.state().freshness).toBe('stale')
    expect(h.fetch.count).toBe(atFailure) // NO immediate follow-up (would be a loop)
    h.scheduler.advance(SYNC_RETRY_DELAY_MS)
    await h.flush()
    expect(h.fetch.count).toBe(atFailure + 1) // only the bounded retry fetches
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
  })

  it('cancels a pending retry timer on a scope change (no lingering fetch)', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'ghost', occurrence_count: 2 })))
    await h.flush()
    h.fetch.rejectNext(new Error('boom'))
    await h.flush()
    expect(h.state().freshness).toBe('stale') // retry scheduled
    h.engine.setScope({ provenance: 'synthetic', filters: { severity: null, detector_id: null, category: null } })
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 's', source_type: 'synthetic' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
    const after = h.fetch.count
    h.scheduler.advance(SYNC_RETRY_DELAY_MS * 2) // the old retry timer must be gone
    await h.flush()
    expect(h.fetch.count).toBe(after)
  })

  it('discards an overflowed buffer when the sync also fails, then recovers on retry', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })]))
    await h.flush()
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'ghost', occurrence_count: 2 })))
    await h.flush() // reconcile sync in flight
    for (let i = 0; i <= WS_BUFFER_MAX; i += 1) {
      h.send(envelope('alert.created', makeAlert({ alert_id: `f${i}` })))
    }
    h.fetch.rejectNext(new Error('boom'))
    await h.flush()
    expect(h.state().freshness).toBe('stale')
    h.scheduler.advance(SYNC_RETRY_DELAY_MS)
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['base']) // flood discarded, not replayed
  })
})

describe('SyncEngine — data retry vs connection retry (corrections)', () => {
  it('schedules the normal delayed snapshot retry after an initial REST failure', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.rejectNext(new Error('boom'))
    await h.flush()
    expect(h.state().freshness).toBe('error')
    const afterFail = h.fetch.count
    // No immediate re-fetch: the bounded retry timer owns the next attempt.
    await h.flush()
    expect(h.fetch.count).toBe(afterFail)
    h.scheduler.advance(SYNC_RETRY_DELAY_MS)
    await h.flush()
    expect(h.fetch.count).toBe(afterFail + 1)
  })

  it('data Retry cancels the pending retry timer, fetches once immediately, without replacing the socket', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.rejectNext(new Error('boom'))
    await h.flush()
    expect(h.state().freshness).toBe('error')
    const afterFail = h.fetch.count
    const socketsAfterFail = h.sockets.length

    h.engine.retryData()
    await h.flush()
    expect(h.fetch.count).toBe(afterFail + 1) // exactly one immediate fetch
    expect(h.sockets).toHaveLength(socketsAfterFail) // healthy socket not replaced

    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')

    // The original (now-cancelled) retry timer must not fire a second fetch.
    const settled = h.fetch.count
    h.scheduler.advance(SYNC_RETRY_DELAY_MS * 2)
    await h.flush()
    expect(h.fetch.count).toBe(settled)
  })

  it('connection Retry replaces the socket exactly once and re-syncs on reopen', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.sockets).toHaveLength(1)
    expect(h.state().freshness).toBe('reconciled')
    const countBefore = h.fetch.count

    h.engine.retryConnection()
    await h.flush()
    expect(h.sockets).toHaveLength(2) // exactly one replacement socket
    expect(h.state().connection).toBe('reconnecting') // awaiting the replacement
    expect(h.fetch.count).toBe(countBefore) // the re-sync waits for the socket to open

    h.connect() // the replacement socket opens
    await h.flush()
    expect(h.fetch.count).toBe(countBefore + 1) // exactly one authoritative re-sync
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a' })]))
    await h.flush()
    expect(h.state().connection).toBe('connected')
    expect(h.state().freshness).toBe('reconciled')
  })
})

describe('SyncEngine — unknown off-page updates and filtered membership (corrections)', () => {
  it('reconciles an unknown off-page update that escalated out of the severity filter', async () => {
    const h = makeEngine(MEDIUM_SCOPE)
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a', severity: 'medium' })], 100))
    await h.flush()
    expect(h.state().total).toBe(100)
    const before = h.fetch.count
    // Unknown id, severity=high (no longer matches the medium filter) — the row
    // was off-page but may previously have counted toward the filtered total.
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'offpage', severity: 'high', occurrence_count: 2 })))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['a']) // never inserted
    expect(h.state().freshness).toBe('pending')
    expect(h.fetch.count).toBe(before + 1) // exactly one reconciliation fetch
  })

  it('installs the authoritative page and corrected total from that reconciliation', async () => {
    const h = makeEngine(MEDIUM_SCOPE)
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a', severity: 'medium' })], 100))
    await h.flush()
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'offpage', severity: 'high', occurrence_count: 2 })))
    await h.flush()
    // The authoritative snapshot reflects the departed row: total 99, new page.
    h.fetch.resolveNext(
      page([makeAlert({ alert_id: 'a', severity: 'medium' }), makeAlert({ alert_id: 'b', severity: 'medium' })], 99),
    )
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['a', 'b'])
    expect(h.state().total).toBe(99)
    expect(h.state().freshness).toBe('reconciled')
  })

  it('ignores an unknown update whose immutable filters cannot affect the scope', async () => {
    const h = makeEngine({
      provenance: 'all',
      filters: { severity: null, detector_id: 'portscan', category: null },
    })
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'a', detector_id: 'portscan' })]))
    await h.flush()
    const before = h.fetch.count
    // detector_id is immutable and does not match the active detector filter, so
    // this update cannot change the filtered page or total.
    h.send(envelope('alert.updated', makeAlert({ alert_id: 'other', detector_id: 'synflood', occurrence_count: 5 })))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['a'])
    expect(h.state().freshness).toBe('reconciled')
    expect(h.fetch.count).toBe(before) // no fetch triggered
  })
})

describe('SyncEngine — no delta exposure before the first REST baseline (corrections)', () => {
  it('reports error with an empty page when the initial snapshot fails', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.rejectNext(new Error('initial boom'))
    await h.flush()
    expect(h.state().freshness).toBe('error')
    expect(h.state().alerts).toHaveLength(0)
  })

  it('never admits a matching created that arrives before the retry timer fires', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.rejectNext(new Error('initial boom'))
    await h.flush()
    const afterFail = h.fetch.count
    // A matching created in the gap between the failed initial snapshot and its
    // bounded retry: no sync is buffering, and there is no baseline to merge into.
    h.send(envelope('alert.created', makeAlert({ alert_id: 'early' })))
    await h.flush()
    expect(h.state().alerts).toHaveLength(0) // no incomplete feed exposed
    expect(h.state().freshness).toBe('error') // still the initial error state
    expect(h.fetch.count).toBe(afterFail) // coalesced; retry delay not bypassed
  })

  it('retries with a fresh buffer and installs the authoritative page normally', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.rejectNext(new Error('initial boom'))
    await h.flush()
    h.send(envelope('alert.created', makeAlert({ alert_id: 'early' }))) // pre-baseline: not admitted
    h.scheduler.advance(SYNC_RETRY_DELAY_MS)
    await h.flush()
    // The retry runs with a fresh buffer and consumes the outstanding dirty flag;
    // its authoritative snapshot is the ONLY source of the visible page.
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'early' }), makeAlert({ alert_id: 'base' })], 2))
    await h.flush()
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['early', 'base'])
    expect(h.state().total).toBe(2)
    expect(h.state().freshness).toBe('reconciled')
    expect(h.fetch.pendingCount).toBe(0) // the retry itself satisfied the reconcile
  })

  it('handles a created during the retry sync only through the snapshot+buffer protocol', async () => {
    const h = makeEngine()
    h.engine.start()
    h.connect()
    await h.flush()
    h.fetch.rejectNext(new Error('initial boom'))
    await h.flush()
    h.scheduler.advance(SYNC_RETRY_DELAY_MS)
    await h.flush() // retry snapshot fetch now in flight, fresh buffer active
    h.send(envelope('alert.created', makeAlert({ alert_id: 'during' }))) // buffered, not applied
    expect(h.state().alerts).toHaveLength(0) // still nothing visible mid-sync
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'base' })], 1))
    await h.flush()
    // Snapshot installed, then the buffered created drained onto it (optimistic,
    // pending the coalesced authoritative follow-up).
    expect(h.state().alerts.map((a) => a.alert_id)).toEqual(['during', 'base'])
    expect(h.state().freshness).toBe('pending')
    h.fetch.resolveNext(page([makeAlert({ alert_id: 'during' }), makeAlert({ alert_id: 'base' })], 2))
    await h.flush()
    expect(h.state().freshness).toBe('reconciled')
  })
})
