/**
 * Time rendering helpers (approved plan §4, docs/API.md §1.1).
 *
 * Alert timestamps are canonical LOGICAL EVENT TIME, not wall clock. Only live
 * events (ts ~ real time) may be shown wall-clock-relative; synthetic and replay
 * timestamps are rendered as raw event-time seconds and must NEVER be shown as
 * "N minutes ago".
 */
/**
 * A safe ISO-8601 string, or undefined for a value outside JavaScript Date's
 * representable range (rendering must never throw). Only used for LIVE alerts,
 * whose timestamps are real wall-clock time.
 */
export function safeIso(epochSeconds: number): string | undefined {
  const ms = epochSeconds * 1000
  if (!Number.isFinite(ms)) return undefined
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return undefined
  try {
    return date.toISOString()
  } catch {
    return undefined
  }
}

export function formatAbsoluteUtc(epochSeconds: number): string {
  const iso = safeIso(epochSeconds)
  if (iso === undefined) return 'unknown time'
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`
}

/**
 * Raw logical event-time seconds, e.g. "t = 1000.0s". Magnitudes too large for
 * a readable fixed rendering (far beyond Date's representable range) use
 * exponential notation instead, e.g. "t = 1e+20s".
 */
export function formatEventSeconds(epochSeconds: number): string {
  if (Math.abs(epochSeconds) >= 1e15) return `t = ${epochSeconds.toExponential()}s`
  return `t = ${epochSeconds.toFixed(1)}s`
}

/** A provenance-independent duration in seconds, e.g. "10.0s". */
export function formatDurationSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '—'
  return `${seconds.toFixed(1)}s`
}

/** "N second(s)/minute(s)/hour(s)/day(s)" for a positive duration in seconds. */
function describeMagnitude(seconds: number): string {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`
  const days = Math.round(hours / 24)
  return `${days} day${days === 1 ? '' : 's'}`
}

/**
 * Wall-clock-relative phrasing — only ever used for the live provenance.
 *
 * Timestamps within ~5 s of now (either direction — small clock skew) read
 * "just now". A timestamp meaningfully in the FUTURE reads "in N …", never
 * "just now": treating a future time as the recent past would misrepresent it.
 */
export function formatRelative(epochSeconds: number, nowMs: number = Date.now()): string {
  const deltaSeconds = Math.round((nowMs - epochSeconds * 1000) / 1000)
  if (Math.abs(deltaSeconds) < 5) return 'just now'
  if (deltaSeconds < 0) return `in ${describeMagnitude(-deltaSeconds)}`
  return `${describeMagnitude(deltaSeconds)} ago`
}
