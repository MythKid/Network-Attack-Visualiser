/**
 * Domain types mirroring the backend Alert model and enums
 * (see backend/app/models/alert.py, enums.py and docs/ALERT_SCHEMA.md §2).
 *
 * These are compile-time shapes only; untrusted JSON is checked at runtime by
 * the guards in src/validation before it is trusted as one of these types.
 */

export type SourceType = 'synthetic' | 'replay' | 'live'
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type Category = 'reconnaissance' | 'dos'
export type AIStatus = 'none' | 'generated' | 'fallback' | 'error'

/** The two V1 detectors; an unknown detector filter is a backend 422. */
export type DetectorId = 'portscan' | 'synflood'

export const SOURCE_TYPES: readonly SourceType[] = ['synthetic', 'replay', 'live']
export const PROTOCOLS: readonly Protocol[] = ['TCP', 'UDP', 'ICMP', 'OTHER']
export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical']
export const CATEGORIES: readonly Category[] = ['reconnaissance', 'dos']
export const AI_STATUSES: readonly AIStatus[] = ['none', 'generated', 'fallback', 'error']
export const DETECTOR_IDS: readonly DetectorId[] = ['portscan', 'synflood']

/** Ordinal ranking used to decide whether a severity escalates (mirrors backend). */
export const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
}

/** Human-readable labels for the provenance banner (SYNTHETIC / REPLAYED / LIVE-LAB). */
export const SOURCE_TYPE_LABEL: Record<SourceType, string> = {
  synthetic: 'SYNTHETIC',
  replay: 'REPLAYED',
  live: 'LIVE-LAB',
}

/** A persisted alert row (docs/ALERT_SCHEMA.md §2). */
export interface Alert {
  alert_id: string
  created_at: number
  detector_id: string
  detector_version: string
  category: Category
  severity: Severity
  confidence: number
  src_ip: string | null
  dst_ip: string
  window_start: number
  window_end: number
  evidence: Record<string, unknown>
  threshold_snapshot: Record<string, unknown>
  dedup_key: string
  source_type: SourceType
  occurrence_count: number
  last_seen: number
  ai_explanation: string | null
  ai_status: AIStatus
}

/** Response body for GET /api/v1/alerts (docs/API.md §3.1). */
export interface AlertListResponse {
  items: Alert[]
  total: number
  limit: number
  offset: number
}
