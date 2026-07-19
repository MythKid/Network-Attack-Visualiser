/**
 * Runtime validator for WebSocket envelopes (docs/API.md §5).
 *
 * Three outcomes, matching the sync contract:
 *  - a known type with a valid alert -> { kind: 'envelope' } (apply);
 *  - an unknown/malformed envelope shape -> { kind: 'unknown' } (ignore safely);
 *  - a KNOWN type whose alert payload is invalid -> throws ValidationError
 *    (the caller must not mutate state and must trigger a REST re-sync).
 */
import type { AlertEnvelope, AlertEnvelopeType } from '../types/ws.ts'
import { parseAlert } from './alert.ts'
import { isRecord } from './guards.ts'

const KNOWN_TYPES: readonly AlertEnvelopeType[] = ['alert.created', 'alert.updated']

export type ParsedEnvelope =
  | { kind: 'envelope'; envelope: AlertEnvelope }
  | { kind: 'unknown' }

function isKnownType(value: unknown): value is AlertEnvelopeType {
  return typeof value === 'string' && (KNOWN_TYPES as readonly string[]).includes(value)
}

/**
 * Parse an already-JSON-decoded WebSocket message.
 * @throws ValidationError when the envelope type is known but its alert is invalid.
 */
export function parseEnvelope(value: unknown): ParsedEnvelope {
  if (!isRecord(value) || !isKnownType(value.type)) {
    return { kind: 'unknown' }
  }
  // Known type: the alert must be valid, or this is a desync signal (throws).
  const alert = parseAlert(value.alert, `envelope(${value.type}).alert`)
  return { kind: 'envelope', envelope: { type: value.type, alert } }
}
