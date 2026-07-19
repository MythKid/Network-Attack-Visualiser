import type { StatsTotals } from '../types/stats.ts'
import { formatBytes, formatInt } from '../utils/format.ts'

/**
 * Overview stat tiles. `alert_count` (distinct alerts) and
 * `alert_occurrence_total` (triggers including reinforcements) are shown as
 * DISTINCT facts — docs/API.md §4 warns against conflating them.
 */
export function SummaryCards({ totals }: { totals: StatsTotals }) {
  const cards = [
    { label: 'Alerts', value: formatInt(totals.alert_count), hint: 'distinct alert rows' },
    {
      label: 'Triggers',
      value: formatInt(totals.alert_occurrence_total),
      hint: 'including reinforcements',
    },
    { label: 'Events', value: formatInt(totals.event_count), hint: 'packets observed' },
    { label: 'Traffic', value: formatBytes(totals.byte_count), hint: 'bytes observed' },
  ]
  return (
    <div className="summary-cards">
      {cards.map((card) => (
        <div className="stat-tile" key={card.label}>
          <span className="stat-label">{card.label}</span>
          <span className="stat-value">{card.value}</span>
          <span className="stat-hint">{card.hint}</span>
        </div>
      ))}
    </div>
  )
}
