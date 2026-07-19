/**
 * Scope helpers: turn the active dashboard scope into REST queries and decide
 * whether a live delta belongs to the current view.
 *
 * Provenance (source_type) scopes both /alerts and /stats; the table-only
 * filters (severity, detector, category) scope only /alerts (docs/API.md §4).
 */
import { ALERT_PAGE_LIMIT } from '../config.ts'
import type { Alert } from '../types/alert.ts'
import type { Scope } from '../types/filters.ts'
import type { AlertQuery, StatsQuery } from '../api/client.ts'

export function scopeToAlertQuery(scope: Scope): AlertQuery {
  return {
    source_type: scope.provenance === 'all' ? null : scope.provenance,
    severity: scope.filters.severity,
    detector_id: scope.filters.detector_id,
    category: scope.filters.category,
    limit: ALERT_PAGE_LIMIT,
    offset: 0,
  }
}

export function scopeToStatsQuery(scope: Scope): StatsQuery {
  return { source_type: scope.provenance === 'all' ? null : scope.provenance }
}

/** True when an alert satisfies the active provenance and all table filters. */
export function alertMatchesScope(alert: Alert, scope: Scope): boolean {
  if (scope.provenance !== 'all' && alert.source_type !== scope.provenance) return false
  const { severity, detector_id, category } = scope.filters
  if (severity !== null && alert.severity !== severity) return false
  if (detector_id !== null && alert.detector_id !== detector_id) return false
  if (category !== null && alert.category !== category) return false
  return true
}

/**
 * True when an `alert.updated` could affect the current query and therefore must
 * be buffered during a sync. `severity` is deliberately NOT checked: it may have
 * escalated a row out of the active severity filter, and that stale-invalidating
 * update must not be dropped. `source_type`, `detector_id` and `category` are
 * immutable for a given alert, so they still gate relevance.
 */
export function updateCouldAffectScope(alert: Alert, scope: Scope): boolean {
  if (scope.provenance !== 'all' && alert.source_type !== scope.provenance) return false
  const { detector_id, category } = scope.filters
  if (detector_id !== null && alert.detector_id !== detector_id) return false
  if (category !== null && alert.category !== category) return false
  return true
}
