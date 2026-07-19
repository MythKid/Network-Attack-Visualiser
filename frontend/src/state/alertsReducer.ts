/**
 * The page-0 alert store and its distinct, envelope-aware operations (§5.2).
 *
 * Admission is separated from version comparison. `occurrence_count` is the
 * monotonic row version (it only grows — docs/API.md §3.3) and governs
 * REPLACEMENT only after the caller has decided a row is allowed in the page:
 *
 *  - installSnapshot: REST only; rebuilds canonical membership/order/total and
 *    may insert rows; a locally held higher-version payload is kept, but a row
 *    absent from the snapshot never survives.
 *  - admitCreated: a scope-matching alert.created may optimistically insert an
 *    absent row (prepend + trim) or version-replace a present one.
 *  - applyUpdate: alert.updated updates ONLY an already-loaded row; an unknown
 *    id is a no-op here (the caller reconciles instead — it is never inserted).
 *  - removeRow: used when a severity escalation moves a row out of the filter.
 *
 * `total` is authoritative only from REST; optimistic insert/remove mark
 * `pendingReconcile` until a snapshot confirms them.
 */
import { ALERT_PAGE_LIMIT } from '../config.ts'
import type { Alert } from '../types/alert.ts'

export interface AlertsState {
  /** alert_id -> Alert. */
  readonly byId: ReadonlyMap<string, Alert>
  /** Canonical recording order (index 0 = newest recorded). */
  readonly order: readonly string[]
  /** Total matching the scope, from the last successful REST snapshot only. */
  readonly total: number
  /** True when an optimistic insert/remove awaits REST confirmation. */
  readonly pendingReconcile: boolean
}

export function emptyAlertsState(): AlertsState {
  return { byId: new Map(), order: [], total: 0, pendingReconcile: false }
}

/** Materialise the ordered page of alerts for rendering. */
export function selectAlerts(state: AlertsState): Alert[] {
  const result: Alert[] = []
  for (const id of state.order) {
    const alert = state.byId.get(id)
    if (alert) result.push(alert)
  }
  return result
}

/** Keep the higher-version payload for the same id (never downgrade). */
function higherVersion(a: Alert, b: Alert): Alert {
  return b.occurrence_count > a.occurrence_count ? b : a
}

/**
 * Rebuild the page from a REST snapshot. Membership, order and total come solely
 * from `alerts`; a locally held row keeps its payload if it is a higher version.
 */
export function installSnapshot(
  state: AlertsState,
  alerts: readonly Alert[],
  total: number,
): AlertsState {
  const byId = new Map<string, Alert>()
  const order: string[] = []
  for (const incoming of alerts) {
    if (byId.has(incoming.alert_id)) continue
    const existing = state.byId.get(incoming.alert_id)
    byId.set(incoming.alert_id, existing ? higherVersion(incoming, existing) : incoming)
    order.push(incoming.alert_id)
  }
  return { byId, order, total, pendingReconcile: false }
}

/**
 * Apply a scope-matching alert.created. Absent -> optimistic prepend + trim;
 * present -> version-gated replace. An insert marks the page pending reconcile.
 */
export function admitCreated(state: AlertsState, alert: Alert): AlertsState {
  const existing = state.byId.get(alert.alert_id)
  if (existing) {
    // Duplicate created: version-gated in-place replace, never a downgrade.
    if (alert.occurrence_count <= existing.occurrence_count) return state
    const byId = new Map(state.byId)
    byId.set(alert.alert_id, alert)
    return { ...state, byId }
  }
  const byId = new Map(state.byId)
  byId.set(alert.alert_id, alert)
  const order = [alert.alert_id, ...state.order]
  while (order.length > ALERT_PAGE_LIMIT) {
    const dropped = order.pop()
    if (dropped !== undefined) byId.delete(dropped)
  }
  return { byId, order, total: state.total, pendingReconcile: true }
}

/**
 * Apply an alert.updated to an already-loaded row (version-gated, in place).
 * An unknown id is a no-op: an update never inserts a row (its recording-order
 * position is unknown). Returns the same reference when nothing changes.
 */
export function applyUpdate(state: AlertsState, alert: Alert): AlertsState {
  const existing = state.byId.get(alert.alert_id)
  if (!existing) return state
  if (alert.occurrence_count <= existing.occurrence_count) return state
  const byId = new Map(state.byId)
  byId.set(alert.alert_id, alert)
  return { ...state, byId }
}

/** Remove a row (membership change); marks the page pending reconcile. */
export function removeRow(state: AlertsState, alertId: string): AlertsState {
  if (!state.byId.has(alertId)) return state
  const byId = new Map(state.byId)
  byId.delete(alertId)
  const order = state.order.filter((id) => id !== alertId)
  return { byId, order, total: state.total, pendingReconcile: true }
}
