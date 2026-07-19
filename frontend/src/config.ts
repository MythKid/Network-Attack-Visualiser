/**
 * Runtime configuration and named tuning constants.
 *
 * The backend base URL comes from VITE_API_BASE_URL (see .env.example); the
 * WebSocket URL is derived from it by swapping the scheme. The browser always
 * reaches the backend on host loopback, so a single default serves both local
 * development and the future Phase 6 loopback-published lab.
 */

const DEFAULT_API_BASE_URL = 'http://localhost:8000'
const WS_PATH = '/api/v1/ws/alerts'

/** Strip any trailing slash so path concatenation stays predictable. */
export function normaliseBaseUrl(raw: string): string {
  const trimmed = raw.trim()
  return trimmed.endsWith('/') ? trimmed.replace(/\/+$/, '') : trimmed
}

/** Derive the WebSocket URL from the REST base URL (http->ws, https->wss). */
export function deriveWsUrl(baseUrl: string): string {
  const url = new URL(WS_PATH, normaliseBaseUrl(baseUrl) + '/')
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  return url.toString()
}

export const API_BASE_URL = normaliseBaseUrl(
  import.meta.env.VITE_API_BASE_URL ?? DEFAULT_API_BASE_URL,
)

export const WS_URL = deriveWsUrl(API_BASE_URL)

// --- Named tuning constants (approved Phase 4 defaults) ----------------------

/** How long to wait for the socket to open before rendering REST offline. */
export const WS_CONNECT_TIMEOUT_MS = 3000
/** Consecutive connect failures before auto-retry stops and a manual retry shows. */
export const WS_FAILURE_CAP = 5
export const WS_BACKOFF_BASE_MS = 500
export const WS_BACKOFF_MAX_MS = 30000
/** Fractional jitter applied to each backoff delay (0..1). */
export const WS_BACKOFF_JITTER = 0.2
/** Trailing debounce before a created-triggered reconciliation runs. */
export const CREATED_RECONCILE_DEBOUNCE_MS = 250
/** Hard ceiling so a continuous created stream cannot postpone reconciliation. */
export const CREATED_RECONCILE_MAX_WAIT_MS = 2000
/** Delay before retrying a failed snapshot fetch through the scheduler. */
export const SYNC_RETRY_DELAY_MS = 2000
/** Maximum deltas buffered during one sync before the run is marked overflowed. */
export const WS_BUFFER_MAX = 500
/** Statistics polling interval while the tab is visible. */
export const STATS_POLL_MS = 5000
/** Page-0 window size (fixed for Phase 4). */
export const ALERT_PAGE_LIMIT = 50
