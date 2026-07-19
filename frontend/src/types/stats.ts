/**
 * Statistics types mirroring the backend StatsResponse
 * (see backend/app/api/schemas.py and docs/API.md §4).
 */
import type { Protocol, Severity, SourceType } from './alert.ts'

export interface StatsTotals {
  /** Alert rows (distinct alerts). */
  alert_count: number
  /** Total triggers including reinforcements; always >= alert_count. */
  alert_occurrence_total: number
  /** Packets over all retained stats buckets. */
  event_count: number
  /** Bytes over all retained stats buckets. */
  byte_count: number
}

export interface ProtocolCount {
  protocol: Protocol
  packet_count: number
  byte_count: number
}

export interface TimelineBucket {
  /** Bucket start in logical event-time epoch seconds (NOT wall clock). */
  bucket_ts: number
  protocol: Protocol
  source_type: SourceType
  packet_count: number
  byte_count: number
}

export interface StatsResponse {
  totals: StatsTotals
  alerts_by_severity: Record<Severity, number>
  alerts_by_detector: Record<string, number>
  alerts_by_source_type: Record<SourceType, number>
  protocol_distribution: ProtocolCount[]
  traffic_timeline: TimelineBucket[]
}
