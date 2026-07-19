/**
 * WebSocket envelope types (docs/API.md §5, docs/ALERT_SCHEMA.md §5).
 * The channel carries live deltas only; history comes from REST.
 */
import type { Alert } from './alert.ts'

export type AlertEnvelopeType = 'alert.created' | 'alert.updated'

export interface AlertEnvelope {
  type: AlertEnvelopeType
  alert: Alert
}
