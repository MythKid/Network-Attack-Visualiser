import { SOURCE_TYPE_LABEL, type Alert } from '../types/alert.ts'
import { formatConfidence, formatFlow } from '../utils/format.ts'
import { formatDurationSeconds } from '../utils/time.ts'
import { AiExplanationSection } from './AiExplanationSection.tsx'
import { EventTime } from './EventTime.tsx'
import { SeverityBadge } from './SeverityBadge.tsx'

function renderValue(value: unknown): string {
  if (value === null) return 'null'
  if (Array.isArray(value)) return value.map((item) => renderValue(item)).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function EvidenceTable({ title, data }: { title: string; data: Record<string, unknown> }) {
  const entries = Object.entries(data)
  return (
    <div className="evidence-block">
      <h4>{title}</h4>
      {entries.length === 0 ? (
        <p className="muted">No fields.</p>
      ) : (
        <dl className="evidence-list">
          {entries.map(([key, value]) => (
            <div key={key} className="evidence-row">
              <dt>{key}</dt>
              <dd className="mono">{renderValue(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  )
}

/**
 * Alert-detail panel: evidence, confidence and severity (heuristic, never
 * asserted as certainty), plus the inert AI section.
 */
export function AlertDetail({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  if (!alert) {
    return (
      <aside className="alert-detail alert-detail-empty" aria-label="Alert details">
        <p className="muted">Select an alert to see its evidence, confidence and severity.</p>
      </aside>
    )
  }
  return (
    <aside className="alert-detail" aria-label={`Alert details for ${alert.detector_id}`}>
      <header className="alert-detail-header">
        <h3>
          {alert.detector_id} <SeverityBadge severity={alert.severity} />
        </h3>
        <button type="button" className="detail-close" onClick={onClose} aria-label="Close details">
          ×
        </button>
      </header>
      <dl className="alert-detail-summary">
        <div>
          <dt>Category</dt>
          <dd>{alert.category}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{formatConfidence(alert.confidence)} (heuristic strength)</dd>
        </div>
        <div>
          <dt>Source → Destination</dt>
          <dd className="mono">{formatFlow(alert.src_ip, alert.dst_ip)}</dd>
        </div>
        <div>
          <dt>Provenance</dt>
          <dd>{SOURCE_TYPE_LABEL[alert.source_type]}</dd>
        </div>
        <div>
          <dt>First recorded</dt>
          <dd>
            <EventTime alert={alert} />
          </dd>
        </div>
        <div>
          <dt>Evidence window</dt>
          <dd>{formatDurationSeconds(alert.window_end - alert.window_start)} (event time)</dd>
        </div>
        <div>
          <dt>Occurrences</dt>
          <dd>{alert.occurrence_count}</dd>
        </div>
      </dl>
      <EvidenceTable title="Evidence" data={alert.evidence} />
      <EvidenceTable title="Threshold snapshot" data={alert.threshold_snapshot} />
      <AiExplanationSection alert={alert} />
    </aside>
  )
}
