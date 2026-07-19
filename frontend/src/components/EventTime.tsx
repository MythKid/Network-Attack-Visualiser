import { SOURCE_TYPE_LABEL, type Alert } from '../types/alert.ts'
import { formatAbsoluteUtc, formatEventSeconds, formatRelative, safeIso } from '../utils/time.ts'

/**
 * Provenance-aware timestamp (AC6, docs/API.md §1.1).
 *
 * LIVE alerts carry real wall-clock time: when the value is representable
 * (safeIso succeeds) they render as a <time> element with a relative label
 * (past or future wording, never a false "just now"), a valid ISO `dateTime`,
 * and an absolute-UTC title. A finite live value OUTSIDE Date's representable
 * range cannot be honestly shown as wall-clock time at all: it renders like the
 * non-live fallback — a plain <span> with raw event seconds + provenance, no
 * <time>, no `dateTime`, no relative wording.
 *
 * SYNTHETIC / REPLAY alerts carry logical event time (often ~1970 epoch): they
 * must NEVER read as wall-clock time, so they render as a plain <span> with raw
 * logical seconds + provenance and NO calendar/Unix `dateTime` and NO 1970 title.
 */
export function EventTime({ alert }: { alert: Alert }) {
  if (alert.source_type === 'live') {
    const iso = safeIso(alert.created_at)
    if (iso !== undefined) {
      return (
        <time className="event-time" title={formatAbsoluteUtc(alert.created_at)} dateTime={iso}>
          {formatRelative(alert.created_at)}
        </time>
      )
    }
    // Finite but not representable as a Date: fall through to the raw rendering.
  }
  const text = `${formatEventSeconds(alert.created_at)} · ${SOURCE_TYPE_LABEL[alert.source_type]} event time`
  return (
    <span className="event-time" title="logical event time (not wall-clock)">
      {text}
    </span>
  )
}
