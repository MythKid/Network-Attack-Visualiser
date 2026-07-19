import type { ConnectionState, Freshness } from '../state/syncEngine.ts'

const CONNECTION_LABEL: Record<ConnectionState, string> = {
  connecting: 'Connecting…',
  connected: 'Live',
  reconnecting: 'Reconnecting…',
  offline: 'Offline',
  capped: 'Offline',
  config_error: 'Connection blocked',
}

const FRESHNESS_LABEL: Record<Freshness, string> = {
  loading: 'Loading…',
  reconciled: 'Reconciled',
  pending: 'Reconciling…',
  stale: 'Stale — retrying',
  error: 'Load failed',
}

/** Live connection state, with a manual retry when auto-retry has stopped. */
export function ConnectionStatus({
  connection,
  onRetry,
}: {
  connection: ConnectionState
  onRetry: () => void
}) {
  const showRetry = connection === 'capped' || connection === 'config_error'
  return (
    <div className={`connection-status connection-${connection}`} role="status">
      <span className="status-dot" aria-hidden="true" />
      <span className="status-label">{CONNECTION_LABEL[connection]}</span>
      {connection === 'config_error' && (
        <span className="status-hint">— serve the dashboard from :5173</span>
      )}
      {showRetry && (
        <button type="button" className="status-retry" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  )
}

/** Data freshness — an independent dimension from the connection (§5.5). */
export function FreshnessBadge({ freshness }: { freshness: Freshness }) {
  return (
    <span className={`freshness-badge freshness-${freshness}`} role="status">
      {FRESHNESS_LABEL[freshness]}
    </span>
  )
}

/**
 * The loaded/total alert-feed counters, with a polite atomic live region so
 * assistive technology is notified when they change (plan §9). The whole table
 * is deliberately NOT a live region — only this compact summary announces, so
 * updates never spam. The visible counter is hidden from the announcement to
 * avoid a doubled/awkward reading of the middot.
 */
export function LiveFeedStatus({ loaded, total }: { loaded: number; total: number }) {
  return (
    <>
      <span className="feed-total muted" aria-hidden="true">
        {loaded} loaded · {total} total in scope
      </span>
      <span className="sr-only" role="status" aria-live="polite" aria-atomic="true">
        {loaded} alerts loaded, {total} total in scope.
      </span>
    </>
  )
}
