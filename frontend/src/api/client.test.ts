import { describe, expect, it, vi } from 'vitest'

import { makeAlert, makeStats } from '../test/factories.ts'
import { ValidationError } from '../validation/guards.ts'
import { ApiError, getAlert, getAlerts, getStats } from './client.ts'

function stubFetch(response: Partial<Response> & { json?: () => Promise<unknown> }) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    ...response,
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function lastUrl(fetchMock: ReturnType<typeof vi.fn>): string {
  return fetchMock.mock.calls[0][0] as string
}

describe('getAlerts', () => {
  it('requests page 0 with no filters and validates the response', async () => {
    const fetchMock = stubFetch({ json: async () => ({ items: [makeAlert()], total: 1, limit: 50, offset: 0 }) })
    const result = await getAlerts()
    expect(result.total).toBe(1)
    expect(lastUrl(fetchMock)).toBe('http://localhost:8000/api/v1/alerts')
  })

  it('encodes provenance and table filters as query parameters', async () => {
    const fetchMock = stubFetch({ json: async () => ({ items: [], total: 0, limit: 50, offset: 0 }) })
    await getAlerts({ source_type: 'synthetic', severity: 'high', detector_id: 'portscan', limit: 50, offset: 0 })
    const url = lastUrl(fetchMock)
    expect(url).toContain('source_type=synthetic')
    expect(url).toContain('severity=high')
    expect(url).toContain('detector_id=portscan')
    expect(url).toContain('limit=50')
  })

  it('raises ApiError with the status on a non-2xx response', async () => {
    stubFetch({ ok: false, status: 422, json: async () => ({}) })
    await expect(getAlerts()).rejects.toMatchObject({ name: 'ApiError', status: 422 })
  })

  it('raises ApiError on malformed JSON', async () => {
    stubFetch({
      json: async () => {
        throw new SyntaxError('Unexpected token')
      },
    })
    await expect(getAlerts()).rejects.toBeInstanceOf(ApiError)
  })

  it('raises ValidationError when the payload does not match the schema', async () => {
    stubFetch({ json: async () => ({ items: [{ bad: true }], total: 1, limit: 50, offset: 0 }) })
    await expect(getAlerts()).rejects.toBeInstanceOf(ValidationError)
  })

  it('propagates an AbortError unchanged (superseded request)', async () => {
    const abort = new DOMException('aborted', 'AbortError')
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(abort))
    await expect(getAlerts()).rejects.toBe(abort)
  })
})

describe('getAlert', () => {
  it('requests a single alert by id', async () => {
    const alert = makeAlert()
    const fetchMock = stubFetch({ json: async () => alert })
    const result = await getAlert(alert.alert_id)
    expect(result.alert_id).toBe(alert.alert_id)
    expect(lastUrl(fetchMock)).toBe(`http://localhost:8000/api/v1/alerts/${alert.alert_id}`)
  })
})

describe('getStats', () => {
  it('scopes stats by provenance only and validates the snapshot', async () => {
    const fetchMock = stubFetch({ json: async () => makeStats() })
    const result = await getStats({ source_type: 'synthetic', buckets: 300 })
    expect(result.totals.alert_count).toBe(1)
    const url = lastUrl(fetchMock)
    expect(url).toContain('/api/v1/stats')
    expect(url).toContain('source_type=synthetic')
    expect(url).toContain('buckets=300')
  })
})
