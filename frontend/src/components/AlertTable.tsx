import { useMemo, useState } from 'react'

import { SEVERITY_ORDER, type Alert } from '../types/alert.ts'
import { formatConfidence, formatFlow } from '../utils/format.ts'
import { EventTime } from './EventTime.tsx'
import { SeverityBadge } from './SeverityBadge.tsx'

type SortKey = 'recorded' | 'severity' | 'detector'

/**
 * The live alert feed: the authoritative page-0 window. Sorting applies to the
 * LOADED rows only — the backend exposes no server-side sort contract
 * (docs/API.md §3), so "Recorded" is the canonical recording order.
 */
function sortAlerts(alerts: readonly Alert[], key: SortKey): Alert[] {
  const rows = [...alerts]
  if (key === 'severity') {
    rows.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
  } else if (key === 'detector') {
    rows.sort((a, b) => a.detector_id.localeCompare(b.detector_id))
  }
  return rows
}

export function AlertTable({
  alerts,
  selectedId,
  onSelect,
}: {
  alerts: Alert[]
  selectedId: string | null
  onSelect: (alertId: string) => void
}) {
  const [sort, setSort] = useState<SortKey>('recorded')
  const rows = useMemo(() => sortAlerts(alerts, sort), [alerts, sort])

  const header = (key: SortKey, label: string) => (
    <th scope="col">
      <button
        type="button"
        className={`sort-button${sort === key ? ' is-active' : ''}`}
        aria-pressed={sort === key}
        onClick={() => setSort(key)}
      >
        {label}
      </button>
    </th>
  )

  return (
    <div className="alert-table-wrapper">
      <table className="alert-table">
        <caption className="sr-only">
          Alerts — loaded page of {alerts.length} rows, sorted by {sort}. Sorting applies to loaded
          rows only.
        </caption>
        <thead>
          <tr>
            {header('recorded', 'Recorded (event time)')}
            {header('severity', 'Severity')}
            {header('detector', 'Detector')}
            <th scope="col">Category</th>
            <th scope="col">Source → Destination</th>
            <th scope="col">Confidence</th>
            <th scope="col">Count</th>
            <th scope="col">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((alert) => {
            const selected = alert.alert_id === selectedId
            return (
              <tr
                key={alert.alert_id}
                className={`alert-row${selected ? ' is-selected' : ''}`}
                onClick={() => onSelect(alert.alert_id)}
              >
                <td>
                  <EventTime alert={alert} />
                </td>
                <td>
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td>{alert.detector_id}</td>
                <td>{alert.category}</td>
                <td className="mono">{formatFlow(alert.src_ip, alert.dst_ip)}</td>
                <td className="num">{formatConfidence(alert.confidence)}</td>
                <td className="num">{alert.occurrence_count}</td>
                <td>
                  <button
                    type="button"
                    className="row-details"
                    aria-pressed={selected}
                    onClick={(event) => {
                      event.stopPropagation()
                      onSelect(alert.alert_id)
                    }}
                  >
                    Details
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
