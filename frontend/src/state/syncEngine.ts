/**
 * SyncEngine: the bounded, single-flight, version-aware synchronisation core
 * (approved plan §5.1, §5.2, §5.4, §5.5). It owns the alert WebSocket, the
 * page-0 store, and the connection/freshness state, and exposes an immutable
 * snapshot for React via useSyncExternalStore.
 *
 * Connection and freshness are independent dimensions (guardrail #2): a REST
 * snapshot can be `reconciled` while the socket is `offline`.
 *
 * All timers are injected so tests are deterministic.
 */
import { getAlerts, type AlertQuery } from '../api/client.ts'
import {
  CREATED_RECONCILE_DEBOUNCE_MS,
  CREATED_RECONCILE_MAX_WAIT_MS,
  SYNC_RETRY_DELAY_MS,
  WS_BUFFER_MAX,
  WS_CONNECT_TIMEOUT_MS,
} from '../config.ts'
import type { Alert, AlertListResponse } from '../types/alert.ts'
import type { Scope } from '../types/filters.ts'
import type { AlertEnvelope } from '../types/ws.ts'
import { parseEnvelope } from '../validation/envelope.ts'
import { AlertSocket, type SocketDeps, type SocketMeta, type SocketPhase } from '../ws/alertSocket.ts'
import {
  admitCreated,
  applyUpdate,
  emptyAlertsState,
  installSnapshot,
  removeRow,
  selectAlerts,
  type AlertsState,
} from './alertsReducer.ts'
import { alertMatchesScope, scopeToAlertQuery, updateCouldAffectScope } from './scope.ts'

export type ConnectionState =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'offline'
  | 'capped'
  | 'config_error'

export type Freshness = 'loading' | 'reconciled' | 'pending' | 'stale' | 'error'

export interface EngineState {
  readonly alerts: Alert[]
  readonly total: number
  readonly connection: ConnectionState
  readonly freshness: Freshness
  /** Increments each time the socket (re)connects; statistics watch this. */
  readonly reconnectNonce: number
}

export interface SyncEngineDeps {
  fetchAlerts: (query: AlertQuery, signal: AbortSignal) => Promise<AlertListResponse>
  setTimer: (callback: () => void, ms: number) => number
  clearTimer: (id: number) => void
  socketDeps?: Partial<SocketDeps>
}

export interface SyncEngineOptions {
  wsUrl: string
  scope: Scope
  deps?: Partial<SyncEngineDeps>
}

interface ConnectWaiter {
  gen: number
  resolve: () => void
  timer: number
}

export class SyncEngine {
  private scope: Scope
  private scopeGen = 0
  private store: AlertsState = emptyAlertsState()

  private readonly socket: AlertSocket
  private readonly fetchAlerts: SyncEngineDeps['fetchAlerts']
  private readonly setTimer: SyncEngineDeps['setTimer']
  private readonly clearTimer: SyncEngineDeps['clearTimer']

  private connection: ConnectionState = 'connecting'
  private socketConnected = false
  private reconnectNonce = 0

  private installedOnce = false
  private initialFailed = false
  private stale = false
  /** True whenever an authoritative reconciliation is scheduled/running/required. */
  private reconcilePending = false
  /** Whether the most recent run produced a clean authoritative snapshot. */
  private lastRunOk = false

  private syncInFlight = false
  private dirty = false
  /** When non-null a sync is buffering deltas for this generation. */
  private activeSyncGen: number | null = null
  private buffer: AlertEnvelope[] = []
  private bufferOverflowed = false
  private currentAbort: AbortController | null = null
  private connectWaiter: ConnectWaiter | null = null

  private createdDebounceTimer: number | null = null
  private createdDeadlineTimer: number | null = null
  private retryTimer: number | null = null

  private started = false
  private disposed = false

  private readonly listeners = new Set<() => void>()
  private snapshot: EngineState

  constructor(options: SyncEngineOptions) {
    this.scope = options.scope
    this.fetchAlerts = options.deps?.fetchAlerts ?? getAlerts
    this.setTimer = options.deps?.setTimer ?? ((cb, ms) => window.setTimeout(cb, ms))
    this.clearTimer = options.deps?.clearTimer ?? ((id) => window.clearTimeout(id))
    this.socket = new AlertSocket({
      url: options.wsUrl,
      onFrame: (data) => this.onFrame(data),
      onState: (phase, meta) => this.onSocketState(phase, meta),
      deps: options.deps?.socketDeps,
    })
    this.snapshot = this.buildSnapshot()
  }

  // --- public surface --------------------------------------------------------

  start(): void {
    if (this.started || this.disposed) return
    this.started = true
    this.socket.start()
    void this.runSync()
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  getState(): EngineState {
    return this.snapshot
  }

  isDisposed(): boolean {
    return this.disposed
  }

  setScope(scope: Scope): void {
    if (this.disposed) return
    // Scope changes supersede immediately: invalidate the previous page, total,
    // optimistic state and any in-flight sync (guardrail #1).
    this.scope = scope
    this.scopeGen += 1
    this.abortInFlight()
    this.cancelCreatedReconcile()
    this.cancelRetry()
    this.dirty = false
    this.buffer = []
    this.bufferOverflowed = false
    this.store = emptyAlertsState()
    this.installedOnce = false
    this.initialFailed = false
    this.stale = false
    this.reconcilePending = false
    this.lastRunOk = false
    this.syncInFlight = false
    this.notify()
    void this.runSync()
  }

  /**
   * User-initiated retry of the REST snapshot/data plane (alert-feed error).
   *
   * Unlike {@link retryConnection} this never touches a healthy socket: it cancels
   * any pending bounded snapshot-retry timer, marks reconciliation pending, and
   * starts exactly one authoritative sync immediately (or, if one is already in
   * flight, requests exactly one follow-up).
   */
  retryData(): void {
    if (this.disposed) return
    // The user overrides the bounded backoff; the retry timer must not later
    // fire a second, redundant fetch.
    this.cancelRetry()
    this.reconcilePending = true
    if (this.syncInFlight) {
      this.dirty = true // exactly one coalesced follow-up
      return
    }
    void this.runSync()
  }

  /**
   * User-initiated retry of the WebSocket connection (capped/offline/blocked).
   *
   * Replaces the socket via the one-attempt lifecycle and requests the
   * authoritative reconciliation the reopened stream requires.
   */
  retryConnection(): void {
    if (this.disposed) return
    this.socket.retryNow()
    this.requestReconcile()
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.abortInFlight()
    this.cancelCreatedReconcile()
    this.cancelRetry()
    this.socket.dispose()
    this.notify()
  }

  // --- socket + frame handling ----------------------------------------------

  private onSocketState(phase: SocketPhase, meta: SocketMeta): void {
    if (this.disposed) return
    switch (phase) {
      case 'connecting':
        this.socketConnected = false
        this.connection = meta.everConnected ? 'reconnecting' : 'connecting'
        break
      case 'connected':
        this.socketConnected = true
        this.connection = 'connected'
        this.reconnectNonce += 1
        if (this.connectWaiter && this.connectWaiter.gen === this.scopeGen) {
          this.resolveConnectWaiter()
        } else {
          this.requestReconcile()
        }
        break
      case 'reconnecting':
        this.socketConnected = false
        this.connection = meta.everConnected ? 'reconnecting' : 'offline'
        break
      case 'capped':
        this.socketConnected = false
        this.connection = 'capped'
        break
      case 'config_error':
        this.socketConnected = false
        this.connection = 'config_error'
        break
      case 'disposed':
        return
    }
    this.notify()
  }

  private onFrame(data: string): void {
    if (this.disposed) return
    let parsed: unknown
    try {
      parsed = JSON.parse(data)
    } catch {
      this.onInvalidFrame()
      return
    }
    let result
    try {
      result = parseEnvelope(parsed)
    } catch {
      // Known type with an invalid alert: a desync signal, never a mutation.
      this.onInvalidFrame()
      return
    }
    if (result.kind === 'unknown') return
    this.applyLive(result.envelope)
    this.notify()
  }

  private onInvalidFrame(): void {
    this.requestReconcile()
    this.notify()
  }

  // --- delta application -----------------------------------------------------

  private applyLive(env: AlertEnvelope): void {
    if (this.activeSyncGen !== null) {
      this.bufferDelta(env)
      return
    }
    // Baseline invariant: before the FIRST successful authoritative REST
    // snapshot, and with no sync actively buffering (e.g. the gap between a
    // failed initial snapshot and its bounded retry), a delta must never admit
    // or display a row — that would expose an incomplete feed as if it were the
    // page. Relevant deltas only mark reconciliation required; the retry (which
    // always begins with a fresh buffer) is the sole path to visible data.
    if (!this.installedOnce) {
      if (env.type === 'alert.created' || updateCouldAffectScope(env.alert, this.scope)) {
        this.requestReconcile()
      }
      return
    }
    if (env.type === 'alert.created') {
      if (alertMatchesScope(env.alert, this.scope)) {
        this.store = admitCreated(this.store, env.alert)
      }
      // Every created may globally prune a row in the filtered view.
      this.onCreatedObserved()
      return
    }
    // alert.updated — compare the version BEFORE evaluating membership, so a
    // stale out-of-scope update can never remove a newer in-scope row.
    const id = env.alert.alert_id
    const existing = this.store.byId.get(id)
    if (existing) {
      if (env.alert.occurrence_count <= existing.occurrence_count) return // stale/idempotent
      if (alertMatchesScope(env.alert, this.scope)) {
        this.store = applyUpdate(this.store, env.alert)
      } else {
        // Newer payload left the active filter: drop it and reconcile to backfill.
        this.store = removeRow(this.store, id)
        this.requestReconcile()
      }
    } else if (updateCouldAffectScope(env.alert, this.scope)) {
      // Unknown id whose update could affect the current query: reconcile, never
      // insert directly. Deliberately NOT alertMatchesScope — an off-page row
      // that just escalated OUT of the active severity filter no longer matches,
      // yet the filtered page/total may have changed. Only the immutable
      // provenance/detector/category facts gate relevance here; this same rule
      // applies to buffered replay (drained through this method) as well.
      this.requestReconcile()
    }
  }

  private bufferDelta(env: AlertEnvelope): void {
    if (env.type === 'alert.created') {
      // Any created during a sync forces exactly one follow-up reconcile
      // (ALERT_MAX_ROWS pruning is global); only scope-matching ones are shown.
      this.dirty = true
      this.reconcilePending = true
      if (!alertMatchesScope(env.alert, this.scope)) return
    } else {
      // Buffer an update that could affect the current query — do NOT require the
      // (possibly escalated) severity to match, so a stale in-flight snapshot can
      // still be invalidated on replay.
      if (!updateCouldAffectScope(env.alert, this.scope)) return
    }
    if (this.bufferOverflowed) return
    if (this.buffer.length >= WS_BUFFER_MAX) {
      this.bufferOverflowed = true
      this.reconcilePending = true
      return
    }
    this.buffer.push(env)
  }

  private onCreatedObserved(): void {
    this.reconcilePending = true
    if (this.syncInFlight || this.retryTimer !== null) {
      this.dirty = true
      return
    }
    this.scheduleCreatedReconcile()
  }

  // --- sync run --------------------------------------------------------------

  private requestReconcile(): void {
    if (this.disposed) return
    this.reconcilePending = true
    // While a run is in flight OR a bounded retry is pending, coalesce into the
    // dirty flag and let that run / the retry timer initiate the next fetch — a
    // reconcile request must never bypass the retry delay into a rapid loop.
    if (this.syncInFlight || this.retryTimer !== null) {
      this.dirty = true
      return
    }
    void this.runSync()
  }

  private async runSync(): Promise<void> {
    if (this.disposed) return
    const gen = this.scopeGen
    this.syncInFlight = true
    // A fresh run addresses all outstanding reconcile needs; deltas arriving
    // during it will set dirty again for a follow-up.
    this.dirty = false
    this.lastRunOk = false
    // Re-syncing over an existing snapshot is a pending reconciliation; the
    // initial load (no snapshot yet) stays "loading" instead.
    if (this.installedOnce) this.reconcilePending = true
    this.activeSyncGen = gen
    this.buffer = []
    this.bufferOverflowed = false
    const abort = new AbortController()
    this.currentAbort = abort

    await this.waitForConnect(gen)
    if (gen !== this.scopeGen || this.disposed) {
      this.finishSync(gen)
      return
    }

    try {
      const page = await this.fetchAlerts(scopeToAlertQuery(this.scope), abort.signal)
      if (gen !== this.scopeGen || this.disposed) {
        this.finishSync(gen)
        return
      }
      this.onSnapshotSuccess(page)
    } catch (error) {
      if (this.isAbort(error) || gen !== this.scopeGen || this.disposed) {
        this.finishSync(gen)
        return
      }
      this.onSnapshotFailure()
    }
    this.finishSync(gen)
  }

  private onSnapshotSuccess(page: AlertListResponse): void {
    // A successful authoritative snapshot cancels any pending failure retry.
    this.cancelRetry()
    this.store = installSnapshot(this.store, page.items, page.total)
    this.installedOnce = true
    this.initialFailed = false
    if (this.bufferOverflowed) {
      // Discard the incomplete buffer; require a fresh authoritative follow-up
      // (with a new buffer) before the view is canonical again.
      this.buffer = []
      this.activeSyncGen = null
      this.stale = true
      this.dirty = true
      this.reconcilePending = true
      this.lastRunOk = true // the install succeeded; the follow-up runs immediately
      return
    }
    // Drain buffered deltas onto the fresh snapshot, then go live.
    const buffered = this.buffer
    this.buffer = []
    this.activeSyncGen = null
    for (const env of buffered) this.applyLive(env)
    this.stale = false
    this.lastRunOk = true
  }

  private onSnapshotFailure(): void {
    this.activeSyncGen = null
    this.lastRunOk = false
    if (!this.installedOnce) {
      // No prior snapshot: do not present buffered deltas as a feed.
      this.buffer = []
      this.initialFailed = true
      this.stale = false
    } else if (this.bufferOverflowed) {
      // An overflowed run that also failed: discard the partial buffer entirely;
      // a fresh-buffer authoritative retry is required.
      this.buffer = []
      this.stale = true
    } else {
      // Preserve the last good snapshot; replay valid buffered deltas onto it.
      const buffered = this.buffer
      this.buffer = []
      for (const env of buffered) this.applyLive(env)
      this.stale = true
    }
    this.reconcilePending = true
    this.scheduleRetry()
  }

  private finishSync(gen: number): void {
    if (gen !== this.scopeGen) {
      this.notify()
      return
    }
    this.currentAbort = null
    this.syncInFlight = false

    // A clean success with a coalesced follow-up: start it immediately and keep
    // reconcile pending — never publish an intermediate "reconciled" state.
    if (this.lastRunOk && this.dirty && !this.disposed) {
      this.dirty = false
      this.notify()
      void this.runSync()
      return
    }
    // Final clean authoritative snapshot with nothing outstanding: reconciled.
    if (this.lastRunOk && !this.dirty && !this.stale) {
      this.reconcilePending = false
    }
    // A failed run does NOT start a dirty follow-up here — the bounded retry
    // timer (scheduled in onSnapshotFailure) is the sole re-trigger.
    this.notify()
  }

  private waitForConnect(gen: number): Promise<void> {
    if (this.socketConnected) return Promise.resolve()
    return new Promise<void>((resolve) => {
      const timer = this.setTimer(() => {
        if (this.connectWaiter && this.connectWaiter.gen === gen) {
          this.connectWaiter = null
          resolve()
        }
      }, WS_CONNECT_TIMEOUT_MS)
      this.connectWaiter = { gen, resolve, timer }
    })
  }

  private resolveConnectWaiter(): void {
    const waiter = this.connectWaiter
    if (!waiter) return
    this.connectWaiter = null
    this.clearTimer(waiter.timer)
    waiter.resolve()
  }

  private abortInFlight(): void {
    if (this.currentAbort) {
      this.currentAbort.abort()
      this.currentAbort = null
    }
    this.resolveConnectWaiter()
    this.activeSyncGen = null
  }

  private isAbort(error: unknown): boolean {
    return error instanceof DOMException && error.name === 'AbortError'
  }

  // --- reconcile scheduling --------------------------------------------------

  private scheduleCreatedReconcile(): void {
    if (this.createdDebounceTimer !== null) this.clearTimer(this.createdDebounceTimer)
    this.createdDebounceTimer = this.setTimer(
      () => this.fireCreatedReconcile(),
      CREATED_RECONCILE_DEBOUNCE_MS,
    )
    // The hard deadline is set once so a continuous stream cannot postpone it.
    if (this.createdDeadlineTimer === null) {
      this.createdDeadlineTimer = this.setTimer(
        () => this.fireCreatedReconcile(),
        CREATED_RECONCILE_MAX_WAIT_MS,
      )
    }
  }

  private fireCreatedReconcile(): void {
    this.cancelCreatedReconcile()
    this.requestReconcile()
  }

  private cancelCreatedReconcile(): void {
    if (this.createdDebounceTimer !== null) {
      this.clearTimer(this.createdDebounceTimer)
      this.createdDebounceTimer = null
    }
    if (this.createdDeadlineTimer !== null) {
      this.clearTimer(this.createdDeadlineTimer)
      this.createdDeadlineTimer = null
    }
  }

  private scheduleRetry(): void {
    if (this.disposed || this.retryTimer !== null) return
    this.retryTimer = this.setTimer(() => {
      this.retryTimer = null
      if (!this.disposed) void this.runSync()
    }, SYNC_RETRY_DELAY_MS)
  }

  private cancelRetry(): void {
    if (this.retryTimer !== null) {
      this.clearTimer(this.retryTimer)
      this.retryTimer = null
    }
  }

  // --- snapshot --------------------------------------------------------------

  private computeFreshness(): Freshness {
    if (!this.installedOnce) return this.initialFailed ? 'error' : 'loading'
    if (this.stale) return 'stale'
    if (this.reconcilePending) return 'pending'
    return 'reconciled'
  }

  private buildSnapshot(): EngineState {
    return {
      alerts: selectAlerts(this.store),
      total: this.store.total,
      connection: this.connection,
      freshness: this.computeFreshness(),
      reconnectNonce: this.reconnectNonce,
    }
  }

  private notify(): void {
    this.snapshot = this.buildSnapshot()
    for (const listener of this.listeners) listener()
  }
}
