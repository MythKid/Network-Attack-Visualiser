/**
 * The live alert WebSocket transport (docs/API.md §5).
 *
 * This layer is deliberately domain-free: it delivers raw text frames and
 * connection-phase changes. Validation, buffering and reducer application live
 * in the sync scheduler. It implements the one-attempt lifecycle from the
 * approved plan (§5.4):
 *
 *  - exactly one active attempt (attempt id) + one reconnect timer + a
 *    per-attempt `finalized` flag; each attempt is finalized once and late
 *    events from stale attempts do nothing;
 *  - `onerror` records diagnostics only and never schedules a retry — the
 *    paired close or the connect-timeout does;
 *  - the connect-timeout handler finalizes its attempt, schedules the single
 *    reconnect itself, then closes/invalidates the socket (it never depends on
 *    a later close from the stale socket);
 *  - explicit finalisation reasons: dispose -> no reconnect; connect timeout ->
 *    reconnect; manual replacement -> replacement already started; remote close
 *    (including remote 1000) -> reconnect; explicit 1008 -> terminal config
 *    error;
 *  - a successful open resets the failure/backoff counters; 1006 is not
 *    terminal; after WS_FAILURE_CAP consecutive failures auto-retry stops and a
 *    manual retry is required.
 *
 * Timers and randomness are injected so tests are deterministic.
 */
import {
  WS_BACKOFF_BASE_MS,
  WS_BACKOFF_JITTER,
  WS_BACKOFF_MAX_MS,
  WS_CONNECT_TIMEOUT_MS,
  WS_FAILURE_CAP,
} from '../config.ts'

/** Close code 1008 (policy violation) — an Origin/config rejection: terminal. */
export const WS_CLOSE_POLICY_VIOLATION = 1008

// Browser timer handle. `setTimeout` in the DOM returns a number; using a
// concrete type keeps this stable whether or not Node's global typings leak in
// through a test-only dependency.
type TimerId = number

export interface SocketMessage {
  readonly data: unknown
}

export interface SocketCloseInfo {
  readonly code: number
  readonly reason: string
}

/** The minimal WebSocket surface used here (browser WebSocket satisfies it). */
export interface WebSocketLike {
  onopen: (() => void) | null
  onmessage: ((event: SocketMessage) => void) | null
  onerror: (() => void) | null
  onclose: ((event: SocketCloseInfo) => void) | null
  close(code?: number, reason?: string): void
}

export interface SocketDeps {
  createSocket: (url: string) => WebSocketLike
  setTimer: (callback: () => void, ms: number) => TimerId
  clearTimer: (id: TimerId) => void
  random: () => number
}

export type SocketPhase =
  | 'connecting'
  | 'connected'
  | 'reconnecting'
  | 'capped'
  | 'config_error'
  | 'disposed'

export interface SocketMeta {
  everConnected: boolean
  failureCount: number
  lastCloseCode: number | null
}

export interface AlertSocketOptions {
  url: string
  onFrame: (data: string) => void
  onState: (phase: SocketPhase, meta: SocketMeta) => void
  deps?: Partial<SocketDeps>
}

interface Attempt {
  id: number
  socket: WebSocketLike
  finalized: boolean
  connectTimer: TimerId | null
}

function browserSocket(url: string): WebSocketLike {
  const ws = new WebSocket(url)
  const adapter: WebSocketLike = {
    onopen: null,
    onmessage: null,
    onerror: null,
    onclose: null,
    close: (code, reason) => ws.close(code, reason),
  }
  ws.onopen = () => adapter.onopen?.()
  ws.onmessage = (event: MessageEvent) => adapter.onmessage?.({ data: event.data })
  ws.onerror = () => adapter.onerror?.()
  ws.onclose = (event: CloseEvent) => adapter.onclose?.({ code: event.code, reason: event.reason })
  return adapter
}

const DEFAULT_DEPS: SocketDeps = {
  createSocket: browserSocket,
  // window.setTimeout is the DOM overload (returns number); the bare global is
  // augmented by Node's typings when a test dependency pulls them in.
  setTimer: (callback, ms) => window.setTimeout(callback, ms),
  clearTimer: (id) => window.clearTimeout(id),
  random: () => Math.random(),
}

/** Exponential backoff with symmetric jitter; delay for the Nth consecutive failure. */
export function computeBackoffDelay(failureCount: number, random: number): number {
  const exponent = Math.max(0, failureCount - 1)
  const base = Math.min(WS_BACKOFF_MAX_MS, WS_BACKOFF_BASE_MS * 2 ** exponent)
  const jitterFactor = 1 + WS_BACKOFF_JITTER * (2 * random - 1)
  return Math.max(0, Math.round(base * jitterFactor))
}

export class AlertSocket {
  private readonly url: string
  private readonly onFrame: (data: string) => void
  private readonly onState: (phase: SocketPhase, meta: SocketMeta) => void
  private readonly deps: SocketDeps

  private attempt: Attempt | null = null
  private reconnectTimer: TimerId | null = null
  private attemptSeq = 0
  private failureCount = 0
  private everConnected = false
  private lastCloseCode: number | null = null
  private disposed = false

  constructor(options: AlertSocketOptions) {
    this.url = options.url
    this.onFrame = options.onFrame
    this.onState = options.onState
    this.deps = { ...DEFAULT_DEPS, ...options.deps }
  }

  /** Begin connecting. Safe to call once; use {@link retryNow} to force a retry. */
  start(): void {
    if (this.disposed || this.attempt || this.reconnectTimer !== null) return
    this.openAttempt()
  }

  /** User-initiated retry: cancel timers, invalidate the old attempt, start one replacement. */
  retryNow(): void {
    if (this.disposed) return
    this.clearReconnectTimer()
    this.invalidateAttempt()
    this.failureCount = 0
    this.openAttempt()
  }

  /** Permanently stop: no further reconnects; releases the socket and timers. */
  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.clearReconnectTimer()
    this.invalidateAttempt()
    this.emit('disposed')
  }

  private emit(phase: SocketPhase): void {
    this.onState(phase, {
      everConnected: this.everConnected,
      failureCount: this.failureCount,
      lastCloseCode: this.lastCloseCode,
    })
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer !== null) {
      this.deps.clearTimer(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  /** Finalize and close the current attempt without triggering reconnect logic. */
  private invalidateAttempt(): void {
    const attempt = this.attempt
    if (!attempt) return
    attempt.finalized = true
    if (attempt.connectTimer !== null) {
      this.deps.clearTimer(attempt.connectTimer)
      attempt.connectTimer = null
    }
    this.attempt = null
    try {
      attempt.socket.close()
    } catch {
      // Closing an already-closing socket is not an error worth surfacing.
    }
  }

  private openAttempt(): void {
    const id = ++this.attemptSeq
    const socket = this.deps.createSocket(this.url)
    const attempt: Attempt = { id, socket, finalized: false, connectTimer: null }
    this.attempt = attempt

    attempt.connectTimer = this.deps.setTimer(() => this.onConnectTimeout(id), WS_CONNECT_TIMEOUT_MS)
    socket.onopen = () => this.onOpen(id)
    socket.onmessage = (event) => this.onMessage(id, event)
    socket.onerror = () => this.onError(id)
    socket.onclose = (event) => this.onClose(id, event)

    this.emit('connecting')
  }

  private isCurrent(id: number): boolean {
    return this.attempt !== null && this.attempt.id === id && !this.attempt.finalized
  }

  /** Mark the identified attempt terminal; returns false if it was already finalized/stale. */
  private finalize(id: number): boolean {
    if (!this.isCurrent(id)) return false
    const attempt = this.attempt as Attempt
    attempt.finalized = true
    if (attempt.connectTimer !== null) {
      this.deps.clearTimer(attempt.connectTimer)
      attempt.connectTimer = null
    }
    return true
  }

  private onOpen(id: number): void {
    if (!this.isCurrent(id)) return
    const attempt = this.attempt as Attempt
    if (attempt.connectTimer !== null) {
      this.deps.clearTimer(attempt.connectTimer)
      attempt.connectTimer = null
    }
    this.everConnected = true
    this.failureCount = 0
    this.emit('connected')
  }

  private onMessage(id: number, event: SocketMessage): void {
    if (!this.isCurrent(id)) return
    if (typeof event.data === 'string') {
      this.onFrame(event.data)
    }
    // Non-string frames (the channel is text-only) are ignored, not fatal.
  }

  private onError(id: number): void {
    if (!this.isCurrent(id)) return
    // Diagnostics only: never schedule a retry here. The paired close (or the
    // connect timeout) owns the single reconnect decision.
  }

  private onClose(id: number, event: SocketCloseInfo): void {
    if (!this.finalize(id)) return
    this.attempt = null
    if (this.disposed) return
    this.lastCloseCode = event.code
    if (event.code === WS_CLOSE_POLICY_VIOLATION) {
      // Origin/config rejection — retrying cannot fix it.
      this.emit('config_error')
      return
    }
    this.failureCount += 1
    this.scheduleReconnect()
  }

  private onConnectTimeout(id: number): void {
    if (!this.finalize(id)) return
    const attempt = this.attempt as Attempt
    this.attempt = null
    // Release the stale socket; its later close is ignored (already finalized).
    try {
      attempt.socket.close()
    } catch {
      // ignore
    }
    if (this.disposed) return
    this.failureCount += 1
    this.scheduleReconnect()
  }

  private scheduleReconnect(): void {
    if (this.disposed) return
    if (this.failureCount >= WS_FAILURE_CAP) {
      this.emit('capped')
      return
    }
    const delay = computeBackoffDelay(this.failureCount, this.deps.random())
    this.emit('reconnecting')
    this.reconnectTimer = this.deps.setTimer(() => {
      this.reconnectTimer = null
      this.openAttempt()
    }, delay)
  }
}
