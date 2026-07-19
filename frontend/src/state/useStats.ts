/**
 * Provenance-scoped statistics polling (approved plan §3.1).
 *
 * WebSocket deltas describe alerts, not all traffic-stat updates, so /stats is
 * refreshed independently: immediately on mount and provenance change, every
 * STATS_POLL_MS while the tab is visible, once when the tab becomes visible
 * again, and once whenever the socket reconnects (reconnectNonce changes).
 * Polling is SINGLE-FLIGHT per effect generation: at most one request is in
 * flight, an overlapping tick never aborts/replaces it (a request slower than
 * the poll interval must not be aborted forever), and coalesced ticks start at
 * most one queued follow-up after the pending request settles. Only the effect
 * cleanup (provenance change, reconnect nonce change, unmount) aborts the
 * superseded request, so a stale response never overwrites newer state.
 * Statistics are scoped by provenance ONLY — the table-only filters
 * (severity/detector/category) do not scope /stats (docs/API.md §4).
 *
 * Every result is tagged with the provenance that produced it, and a render
 * SYNCHRONOUSLY masks any result whose provenance is not the current one, so a
 * previous scope's numbers can never appear under a new provenance banner (not
 * relying on useEffect cleanup timing). Failures are provenance-aware: a failure
 * for the CURRENT provenance retains its last successful data and marks it stale,
 * while the FIRST failed request for a NEW provenance surfaces a clean error
 * (data=null, loading=false, error=true, stale=false) rather than retaining — and
 * masking — the previous provenance's numbers into an endless loading state.
 */
import { useEffect, useState } from 'react'

import { getStats } from '../api/client.ts'
import { STATS_POLL_MS } from '../config.ts'
import type { Provenance } from '../types/filters.ts'
import type { StatsResponse } from '../types/stats.ts'

export interface StatsState {
  data: StatsResponse | null
  loading: boolean
  error: boolean
  stale: boolean
}

interface InternalStatsState extends StatsState {
  /** The provenance query that produced `data`. */
  provenance: Provenance | null
}

function isAbort(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

export function useStats(provenance: Provenance, reconnectNonce: number): StatsState {
  const [state, setState] = useState<InternalStatsState>({
    data: null,
    provenance: null,
    loading: true,
    error: false,
    stale: false,
  })

  useEffect(() => {
    let disposed = false
    let controller: AbortController | null = null
    let inFlight = false
    let queuedRefresh = false
    const query = { source_type: provenance === 'all' ? null : provenance }

    const load = () => {
      // Single-flight per effect generation: a poll tick or visibility refresh
      // while a request is pending must NOT abort and replace it (a request
      // slower than STATS_POLL_MS would otherwise be aborted forever). Coalesce
      // into one queued follow-up that starts after the current request settles.
      if (inFlight) {
        queuedRefresh = true
        return
      }
      inFlight = true
      const current = new AbortController()
      controller = current
      getStats(query, current.signal)
        .then((data) => {
          if (!disposed) {
            setState({ data, provenance, loading: false, error: false, stale: false })
          }
        })
        .catch((error: unknown) => {
          if (isAbort(error) || disposed) return
          setState((prev) => {
            // A failure for the SAME provenance keeps its last good data (stale).
            if (prev.provenance === provenance) {
              return {
                data: prev.data,
                provenance,
                loading: false,
                error: true,
                stale: prev.data !== null,
              }
            }
            // The FIRST request for a NEW provenance failed: never retain the
            // previous provenance's data. Surface a clean error for this scope so
            // the synchronous mask does not turn it into an endless load.
            return { data: null, provenance, loading: false, error: true, stale: false }
          })
        })
        .finally(() => {
          inFlight = false
          controller = null
          // At most ONE follow-up, regardless of how many ticks coalesced; the
          // flag is cleared before starting so there is no unbounded chain.
          if (queuedRefresh && !disposed) {
            queuedRefresh = false
            load()
          }
        })
    }

    load()

    const interval = window.setInterval(() => {
      if (!document.hidden) load()
    }, STATS_POLL_MS)
    const onVisibility = () => {
      if (!document.hidden) load()
    }
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      disposed = true
      controller?.abort()
      window.clearInterval(interval)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [provenance, reconnectNonce])

  // Synchronous mask: never expose a previous provenance's statistics under a
  // new provenance banner, even before the effect refetches.
  if (state.provenance !== null && state.provenance !== provenance) {
    return { data: null, loading: true, error: false, stale: false }
  }
  return { data: state.data, loading: state.loading, error: state.error, stale: state.stale }
}
