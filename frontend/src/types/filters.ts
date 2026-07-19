/**
 * Dashboard scope: the global provenance selection plus the table-only filters.
 *
 * Provenance (source_type) scopes BOTH /alerts and /stats; severity, detector
 * and category scope ONLY /alerts (docs/API.md §3.1, §4).
 */
import type { Category, DetectorId, Severity, SourceType } from './alert.ts'

/** The global provenance selector value: a single source or all provenances. */
export type Provenance = 'all' | SourceType

/** Table-only filters (do not scope statistics). */
export interface TableFilters {
  severity: Severity | null
  detector_id: DetectorId | null
  category: Category | null
}

export const EMPTY_TABLE_FILTERS: TableFilters = {
  severity: null,
  detector_id: null,
  category: null,
}

/** The complete active scope that drives REST queries and WS delta filtering. */
export interface Scope {
  provenance: Provenance
  filters: TableFilters
}

export const DEFAULT_SCOPE: Scope = {
  provenance: 'all',
  filters: EMPTY_TABLE_FILTERS,
}
