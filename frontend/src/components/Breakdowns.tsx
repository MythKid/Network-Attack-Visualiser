import { SEVERITIES, type Severity } from '../types/alert.ts'

/** A labelled magnitude bar; identity is the text key, length is the count. */
function BreakdownRow({
  keyLabel,
  keyClass,
  value,
  max,
}: {
  keyLabel: string
  keyClass?: string
  value: number
  max: number
}) {
  const width = max > 0 ? (value / max) * 100 : 0
  return (
    <li className="breakdown-row">
      <span className={`breakdown-key ${keyClass ?? ''}`}>
        {keyClass ? <span className="severity-dot" aria-hidden="true" /> : null}
        {keyLabel}
      </span>
      <span className="breakdown-bar" aria-hidden="true">
        <span className="breakdown-fill" style={{ width: `${width}%` }} />
      </span>
      <span className="breakdown-value num">{value}</span>
    </li>
  )
}

export function SeverityBreakdown({ counts }: { counts: Record<Severity, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((severity) => counts[severity]))
  return (
    <section className="breakdown" aria-label="Alerts by severity">
      <h3>By severity</h3>
      <ul className="breakdown-list">
        {SEVERITIES.map((severity) => (
          <BreakdownRow
            key={severity}
            keyLabel={severity}
            keyClass={`severity-${severity}`}
            value={counts[severity]}
            max={max}
          />
        ))}
      </ul>
    </section>
  )
}

export function DetectorBreakdown({ counts }: { counts: Record<string, number> }) {
  const entries = Object.entries(counts)
  const max = Math.max(1, ...entries.map(([, value]) => value))
  return (
    <section className="breakdown" aria-label="Alerts by detector">
      <h3>By detector</h3>
      {entries.length === 0 ? (
        <p className="muted">No detectors reported.</p>
      ) : (
        <ul className="breakdown-list">
          {entries.map(([detector, value]) => (
            <BreakdownRow key={detector} keyLabel={detector} value={value} max={max} />
          ))}
        </ul>
      )}
    </section>
  )
}
