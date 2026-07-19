/** Runtime validator for the GET /api/v1/stats response. */
import { PROTOCOLS, SEVERITIES, SOURCE_TYPES } from '../types/alert.ts'
import type { Severity, SourceType } from '../types/alert.ts'
import type {
  ProtocolCount,
  StatsResponse,
  StatsTotals,
  TimelineBucket,
} from '../types/stats.ts'
import {
  ValidationError,
  requireEnum,
  requireInteger,
  requireRecord,
  requireString,
} from './guards.ts'

function parseTotals(value: unknown): StatsTotals {
  const raw = requireRecord(value, 'stats.totals')
  return {
    alert_count: requireInteger(raw.alert_count, 'stats.totals.alert_count'),
    alert_occurrence_total: requireInteger(
      raw.alert_occurrence_total,
      'stats.totals.alert_occurrence_total',
    ),
    event_count: requireInteger(raw.event_count, 'stats.totals.event_count'),
    byte_count: requireInteger(raw.byte_count, 'stats.totals.byte_count'),
  }
}

function parseCountMap<K extends string>(
  value: unknown,
  keys: readonly K[],
  path: string,
): Record<K, number> {
  const raw = requireRecord(value, path)
  const result = {} as Record<K, number>
  for (const key of keys) {
    result[key] = requireInteger(raw[key], `${path}.${key}`)
  }
  return result
}

function parseDetectorMap(value: unknown): Record<string, number> {
  const raw = requireRecord(value, 'stats.alerts_by_detector')
  const result: Record<string, number> = {}
  for (const [key, count] of Object.entries(raw)) {
    result[key] = requireInteger(count, `stats.alerts_by_detector.${key}`)
  }
  return result
}

function parseProtocolCount(value: unknown, path: string): ProtocolCount {
  const raw = requireRecord(value, path)
  return {
    protocol: requireEnum(raw.protocol, PROTOCOLS, `${path}.protocol`),
    packet_count: requireInteger(raw.packet_count, `${path}.packet_count`),
    byte_count: requireInteger(raw.byte_count, `${path}.byte_count`),
  }
}

function parseTimelineBucket(value: unknown, path: string): TimelineBucket {
  const raw = requireRecord(value, path)
  const bucketTs = raw.bucket_ts
  if (typeof bucketTs !== 'number' || !Number.isFinite(bucketTs)) {
    throw new ValidationError('expected a finite number', `${path}.bucket_ts`)
  }
  return {
    bucket_ts: bucketTs,
    protocol: requireEnum(raw.protocol, PROTOCOLS, `${path}.protocol`),
    source_type: requireEnum(raw.source_type, SOURCE_TYPES, `${path}.source_type`),
    packet_count: requireInteger(raw.packet_count, `${path}.packet_count`),
    byte_count: requireInteger(raw.byte_count, `${path}.byte_count`),
  }
}

/** Parse and validate the GET /api/v1/stats response; throws on failure. */
export function parseStatsResponse(value: unknown): StatsResponse {
  const raw = requireRecord(value, 'stats')
  if (!Array.isArray(raw.protocol_distribution)) {
    throw new ValidationError('expected an array', 'stats.protocol_distribution')
  }
  if (!Array.isArray(raw.traffic_timeline)) {
    throw new ValidationError('expected an array', 'stats.traffic_timeline')
  }
  // detector ids are validated leniently (the backend derives them from the
  // wired detectors), but their labels must still be strings.
  for (const key of Object.keys(requireRecord(raw.alerts_by_detector, 'stats.alerts_by_detector'))) {
    requireString(key, 'stats.alerts_by_detector.<key>')
  }
  return {
    totals: parseTotals(raw.totals),
    alerts_by_severity: parseCountMap<Severity>(
      raw.alerts_by_severity,
      SEVERITIES,
      'stats.alerts_by_severity',
    ),
    alerts_by_detector: parseDetectorMap(raw.alerts_by_detector),
    alerts_by_source_type: parseCountMap<SourceType>(
      raw.alerts_by_source_type,
      SOURCE_TYPES,
      'stats.alerts_by_source_type',
    ),
    protocol_distribution: raw.protocol_distribution.map((row, i) =>
      parseProtocolCount(row, `stats.protocol_distribution[${i}]`),
    ),
    traffic_timeline: raw.traffic_timeline.map((row, i) =>
      parseTimelineBucket(row, `stats.traffic_timeline[${i}]`),
    ),
  }
}
