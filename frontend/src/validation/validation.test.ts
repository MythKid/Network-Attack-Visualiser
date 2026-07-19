import { describe, expect, it } from 'vitest'

import { makeAlert, makeStats } from '../test/factories.ts'
import { parseAlert, parseAlertListResponse } from './alert.ts'
import { parseEnvelope } from './envelope.ts'
import { ValidationError } from './guards.ts'
import { parseStatsResponse } from './stats.ts'

describe('parseAlert', () => {
  it('accepts a valid alert', () => {
    const alert = makeAlert()
    expect(parseAlert(alert)).toEqual(alert)
  })

  it('rejects a missing required field', () => {
    const { dst_ip: _omitted, ...partial } = makeAlert()
    expect(() => parseAlert(partial)).toThrow(ValidationError)
  })

  it('rejects an invalid severity enum', () => {
    expect(() => parseAlert(makeAlert({ severity: 'urgent' as never }))).toThrow(/severity/)
  })

  it('rejects an invalid source_type enum', () => {
    expect(() => parseAlert(makeAlert({ source_type: 'fabricated' as never }))).toThrow(
      /source_type/,
    )
  })

  it('rejects a non-finite numeric field', () => {
    expect(() => parseAlert(makeAlert({ confidence: Number.NaN }))).toThrow(/confidence/)
    expect(() => parseAlert(makeAlert({ created_at: Number.POSITIVE_INFINITY }))).toThrow(
      /created_at/,
    )
  })

  it('rejects a non-finite value nested inside evidence', () => {
    expect(() =>
      parseAlert(makeAlert({ evidence: { rate: Number.POSITIVE_INFINITY } })),
    ).toThrow(/evidence/)
    expect(() =>
      parseAlert(makeAlert({ evidence: { nested: { deep: [1, Number.NaN] } } })),
    ).toThrow(/evidence/)
  })

  it('rejects a non-object', () => {
    expect(() => parseAlert(null)).toThrow(ValidationError)
    expect(() => parseAlert('nope')).toThrow(ValidationError)
  })
})

describe('parseAlertListResponse', () => {
  it('accepts a valid page', () => {
    const response = { items: [makeAlert(), makeAlert()], total: 2, limit: 50, offset: 0 }
    expect(parseAlertListResponse(response).items).toHaveLength(2)
  })

  it('rejects when items is not an array', () => {
    expect(() =>
      parseAlertListResponse({ items: {}, total: 0, limit: 50, offset: 0 }),
    ).toThrow(/items/)
  })

  it('rejects a non-integer total', () => {
    expect(() =>
      parseAlertListResponse({ items: [], total: 1.5, limit: 50, offset: 0 }),
    ).toThrow(/total/)
  })
})

describe('parseStatsResponse', () => {
  it('accepts a valid stats snapshot', () => {
    const stats = makeStats()
    expect(parseStatsResponse(stats)).toEqual(stats)
  })

  it('rejects a missing severity key', () => {
    const stats = makeStats()
    const broken = { ...stats, alerts_by_severity: { low: 0, medium: 1, high: 0 } }
    expect(() => parseStatsResponse(broken)).toThrow(/critical/)
  })

  it('rejects a non-finite bucket timestamp', () => {
    const stats = makeStats({
      traffic_timeline: [
        {
          bucket_ts: Number.NaN,
          protocol: 'TCP',
          source_type: 'synthetic',
          packet_count: 1,
          byte_count: 1,
        },
      ],
    })
    expect(() => parseStatsResponse(stats)).toThrow(/bucket_ts/)
  })
})

describe('parseEnvelope', () => {
  it('parses a valid created envelope', () => {
    const result = parseEnvelope({ type: 'alert.created', alert: makeAlert() })
    expect(result.kind).toBe('envelope')
  })

  it('parses a valid updated envelope', () => {
    const result = parseEnvelope({ type: 'alert.updated', alert: makeAlert() })
    expect(result.kind).toBe('envelope')
  })

  it('treats an unknown type as ignorable, not an error', () => {
    expect(parseEnvelope({ type: 'alert.deleted', alert: makeAlert() }).kind).toBe('unknown')
    expect(parseEnvelope({ nope: true }).kind).toBe('unknown')
    expect(parseEnvelope(null).kind).toBe('unknown')
  })

  it('throws when a KNOWN type carries an invalid alert (desync signal)', () => {
    expect(() => parseEnvelope({ type: 'alert.created', alert: { bad: true } })).toThrow(
      ValidationError,
    )
    expect(() =>
      parseEnvelope({ type: 'alert.updated', alert: makeAlert({ severity: 'x' as never }) }),
    ).toThrow(ValidationError)
  })
})
