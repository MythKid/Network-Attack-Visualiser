/**
 * REST client for the Phase 3 backend (docs/API.md).
 *
 * GET-only, no credentials, no custom request headers beyond Accept — these are
 * CORS "simple requests" so no preflight is triggered. The dashboard never calls
 * the authenticated ingest endpoint and never holds the sensor token. Every
 * response is runtime-validated (src/validation) before it is trusted; an
 * AbortError from a superseded request propagates unchanged.
 */
import { API_BASE_URL } from '../config.ts'
import type { Alert, AlertListResponse, Category, DetectorId, Severity, SourceType } from '../types/alert.ts'
import type { StatsResponse } from '../types/stats.ts'
import { parseAlert, parseAlertListResponse } from '../validation/alert.ts'
import { parseStatsResponse } from '../validation/stats.ts'

/** A REST-layer failure: a non-2xx status, a network error, or malformed JSON. */
export class ApiError extends Error {
  readonly status: number | undefined

  constructor(message: string, options?: { status?: number; cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined)
    this.name = 'ApiError'
    this.status = options?.status
  }
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

async function fetchJson(
  path: string,
  params: URLSearchParams | undefined,
  signal: AbortSignal | undefined,
): Promise<unknown> {
  const query = params && [...params.keys()].length > 0 ? `?${params.toString()}` : ''
  const url = `${API_BASE_URL}${path}${query}`

  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal,
    })
  } catch (error) {
    if (isAbortError(error)) throw error
    throw new ApiError(`network error requesting ${path}`, { cause: error })
  }

  if (!response.ok) {
    throw new ApiError(`backend returned HTTP ${response.status} for ${path}`, {
      status: response.status,
    })
  }

  try {
    return (await response.json()) as unknown
  } catch (error) {
    throw new ApiError(`invalid JSON in response for ${path}`, { cause: error })
  }
}

export interface AlertQuery {
  severity?: Severity | null
  detector_id?: DetectorId | null
  category?: Category | null
  source_type?: SourceType | null
  limit?: number
  offset?: number
}

export async function getAlerts(
  query: AlertQuery = {},
  signal?: AbortSignal,
): Promise<AlertListResponse> {
  const params = new URLSearchParams()
  if (query.severity) params.set('severity', query.severity)
  if (query.detector_id) params.set('detector_id', query.detector_id)
  if (query.category) params.set('category', query.category)
  if (query.source_type) params.set('source_type', query.source_type)
  if (query.limit !== undefined) params.set('limit', String(query.limit))
  if (query.offset !== undefined) params.set('offset', String(query.offset))
  return parseAlertListResponse(await fetchJson('/api/v1/alerts', params, signal))
}

export async function getAlert(alertId: string, signal?: AbortSignal): Promise<Alert> {
  const path = `/api/v1/alerts/${encodeURIComponent(alertId)}`
  return parseAlert(await fetchJson(path, undefined, signal))
}

export interface StatsQuery {
  source_type?: SourceType | null
  buckets?: number
}

export async function getStats(
  query: StatsQuery = {},
  signal?: AbortSignal,
): Promise<StatsResponse> {
  const params = new URLSearchParams()
  if (query.source_type) params.set('source_type', query.source_type)
  if (query.buckets !== undefined) params.set('buckets', String(query.buckets))
  return parseStatsResponse(await fetchJson('/api/v1/stats', params, signal))
}
