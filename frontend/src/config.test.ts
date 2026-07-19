import { describe, expect, it } from 'vitest'

import { deriveWsUrl, normaliseBaseUrl } from './config.ts'

describe('normaliseBaseUrl', () => {
  it('strips a single trailing slash', () => {
    expect(normaliseBaseUrl('http://localhost:8000/')).toBe('http://localhost:8000')
  })

  it('strips multiple trailing slashes and surrounding whitespace', () => {
    expect(normaliseBaseUrl('  http://localhost:8000///  ')).toBe('http://localhost:8000')
  })

  it('leaves a clean URL unchanged', () => {
    expect(normaliseBaseUrl('http://localhost:8000')).toBe('http://localhost:8000')
  })
})

describe('deriveWsUrl', () => {
  it('maps http to ws and appends the alert feed path', () => {
    expect(deriveWsUrl('http://localhost:8000')).toBe('ws://localhost:8000/api/v1/ws/alerts')
  })

  it('maps https to wss', () => {
    expect(deriveWsUrl('https://example.test')).toBe('wss://example.test/api/v1/ws/alerts')
  })

  it('tolerates a trailing slash on the base URL', () => {
    expect(deriveWsUrl('http://127.0.0.1:8000/')).toBe('ws://127.0.0.1:8000/api/v1/ws/alerts')
  })
})
