/** Runtime validators for Alert and the alert list response. */
import {
  AI_STATUSES,
  CATEGORIES,
  SEVERITIES,
  SOURCE_TYPES,
  type Alert,
  type AlertListResponse,
} from '../types/alert.ts'
import {
  ValidationError,
  requireFiniteJsonRecord,
  requireFiniteNumber,
  requireInteger,
  requireRecord,
  requireString,
  requireStringOrNull,
  requireEnum,
} from './guards.ts'

/** Parse and validate one untrusted value as an {@link Alert}; throws on failure. */
export function parseAlert(value: unknown, path = 'alert'): Alert {
  const raw = requireRecord(value, path)
  return {
    alert_id: requireString(raw.alert_id, `${path}.alert_id`),
    created_at: requireFiniteNumber(raw.created_at, `${path}.created_at`),
    detector_id: requireString(raw.detector_id, `${path}.detector_id`),
    detector_version: requireString(raw.detector_version, `${path}.detector_version`),
    category: requireEnum(raw.category, CATEGORIES, `${path}.category`),
    severity: requireEnum(raw.severity, SEVERITIES, `${path}.severity`),
    confidence: requireFiniteNumber(raw.confidence, `${path}.confidence`),
    src_ip: requireStringOrNull(raw.src_ip, `${path}.src_ip`),
    dst_ip: requireString(raw.dst_ip, `${path}.dst_ip`),
    window_start: requireFiniteNumber(raw.window_start, `${path}.window_start`),
    window_end: requireFiniteNumber(raw.window_end, `${path}.window_end`),
    evidence: requireFiniteJsonRecord(raw.evidence, `${path}.evidence`),
    threshold_snapshot: requireFiniteJsonRecord(
      raw.threshold_snapshot,
      `${path}.threshold_snapshot`,
    ),
    dedup_key: requireString(raw.dedup_key, `${path}.dedup_key`),
    source_type: requireEnum(raw.source_type, SOURCE_TYPES, `${path}.source_type`),
    occurrence_count: requireInteger(raw.occurrence_count, `${path}.occurrence_count`),
    last_seen: requireFiniteNumber(raw.last_seen, `${path}.last_seen`),
    ai_explanation: requireStringOrNull(raw.ai_explanation, `${path}.ai_explanation`),
    ai_status: requireEnum(raw.ai_status, AI_STATUSES, `${path}.ai_status`),
  }
}

/** Parse and validate the GET /api/v1/alerts response; throws on failure. */
export function parseAlertListResponse(value: unknown): AlertListResponse {
  const raw = requireRecord(value, 'alertList')
  if (!Array.isArray(raw.items)) {
    throw new ValidationError('expected an array', 'alertList.items')
  }
  return {
    items: raw.items.map((item, index) => parseAlert(item, `alertList.items[${index}]`)),
    total: requireInteger(raw.total, 'alertList.total'),
    limit: requireInteger(raw.limit, 'alertList.limit'),
    offset: requireInteger(raw.offset, 'alertList.offset'),
  }
}
