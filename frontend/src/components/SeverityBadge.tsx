import type { Severity } from '../types/alert.ts'

/** A severity chip. Colour is a status accent; the text label carries meaning. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`severity-badge severity-${severity}`}>
      <span className="severity-dot" aria-hidden="true" />
      {severity}
    </span>
  )
}
