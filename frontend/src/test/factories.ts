/** Shared test factories for building valid domain objects. */
import type { Alert } from '../types/alert.ts'
import type { StatsResponse } from '../types/stats.ts'
import type { AlertEnvelope, AlertEnvelopeType } from '../types/ws.ts'

let seq = 0

/** A deterministic UUIDv4-shaped id (unique per call unless overridden). */
export function makeAlertId(n = ++seq): string {
  const hex = n.toString(16).padStart(12, '0')
  return `11111111-1111-4111-8111-${hex}`
}

export function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    alert_id: makeAlertId(),
    created_at: 1000,
    detector_id: 'portscan',
    detector_version: '1.0',
    category: 'reconnaissance',
    severity: 'medium',
    confidence: 0.7,
    src_ip: '10.0.0.5',
    dst_ip: '10.0.0.9',
    window_start: 1000,
    window_end: 1010,
    evidence: { distinct_port_count: 15, sampled_ports: [22, 80, 443], duration_s: 10 },
    threshold_snapshot: { PORTSCAN_MIN_PORTS: 15, PORTSCAN_WINDOW_S: 10 },
    dedup_key: 'dedup-portscan',
    source_type: 'synthetic',
    occurrence_count: 1,
    last_seen: 1010,
    ai_explanation: null,
    ai_status: 'none',
    ...overrides,
  }
}

export function makeEnvelope(
  type: AlertEnvelopeType,
  overrides: Partial<Alert> = {},
): AlertEnvelope {
  return { type, alert: makeAlert(overrides) }
}

export function makeStats(overrides: Partial<StatsResponse> = {}): StatsResponse {
  return {
    totals: {
      alert_count: 1,
      alert_occurrence_total: 2,
      event_count: 100,
      byte_count: 6400,
    },
    alerts_by_severity: { low: 0, medium: 1, high: 0, critical: 0 },
    alerts_by_detector: { portscan: 1, synflood: 0 },
    alerts_by_source_type: { synthetic: 1, replay: 0, live: 0 },
    protocol_distribution: [{ protocol: 'TCP', packet_count: 100, byte_count: 6400 }],
    traffic_timeline: [
      { bucket_ts: 1000, protocol: 'TCP', source_type: 'synthetic', packet_count: 5, byte_count: 320 },
    ],
    ...overrides,
  }
}
