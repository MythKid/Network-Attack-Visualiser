import {
  CATEGORIES,
  DETECTOR_IDS,
  SEVERITIES,
  type Category,
  type DetectorId,
  type Severity,
} from '../types/alert.ts'
import type { TableFilters } from '../types/filters.ts'

/**
 * Table-only filters (severity / detector / category). These scope the alert
 * table via /alerts but NOT the provenance-wide statistics (docs/API.md §4).
 */
export function Filters({
  filters,
  onChange,
}: {
  filters: TableFilters
  onChange: (filters: TableFilters) => void
}) {
  return (
    <div className="filters" aria-label="Alert table filters">
      <label className="filter">
        <span>Severity</span>
        <select
          value={filters.severity ?? ''}
          onChange={(event) =>
            onChange({ ...filters, severity: (event.target.value || null) as Severity | null })
          }
        >
          <option value="">All</option>
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </select>
      </label>
      <label className="filter">
        <span>Detector</span>
        <select
          value={filters.detector_id ?? ''}
          onChange={(event) =>
            onChange({ ...filters, detector_id: (event.target.value || null) as DetectorId | null })
          }
        >
          <option value="">All</option>
          {DETECTOR_IDS.map((detector) => (
            <option key={detector} value={detector}>
              {detector}
            </option>
          ))}
        </select>
      </label>
      <label className="filter">
        <span>Category</span>
        <select
          value={filters.category ?? ''}
          onChange={(event) =>
            onChange({ ...filters, category: (event.target.value || null) as Category | null })
          }
        >
          <option value="">All</option>
          {CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {category}
            </option>
          ))}
        </select>
      </label>
    </div>
  )
}
