import { SOURCE_TYPES, type Alert, type SourceType } from '../types/alert.ts'
import type { StatsResponse } from '../types/stats.ts'

/**
 * The provenances actually present, for the "All" banner chips: the union of
 * non-zero stats source counts, timeline source types, and loaded alert rows
 * (approved plan §9). Returned in canonical order.
 */
export function computePresentProvenances(
  stats: StatsResponse | null,
  alerts: readonly Alert[],
): SourceType[] {
  const present = new Set<SourceType>()
  if (stats) {
    for (const source of SOURCE_TYPES) {
      if ((stats.alerts_by_source_type[source] ?? 0) > 0) present.add(source)
    }
    for (const bucket of stats.traffic_timeline) present.add(bucket.source_type)
  }
  for (const alert of alerts) present.add(alert.source_type)
  return SOURCE_TYPES.filter((source) => present.has(source))
}
