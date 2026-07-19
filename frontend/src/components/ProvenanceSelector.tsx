import type { Provenance } from '../types/filters.ts'

const OPTIONS: { value: Provenance; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'synthetic', label: 'Synthetic' },
  { value: 'replay', label: 'Replayed' },
  { value: 'live', label: 'Live-Lab' },
]

/** The global provenance selector — scopes REST, stats and the WS delta filter. */
export function ProvenanceSelector({
  value,
  onChange,
}: {
  value: Provenance
  onChange: (provenance: Provenance) => void
}) {
  return (
    <div className="provenance-selector" role="radiogroup" aria-label="Provenance">
      {OPTIONS.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={value === option.value}
          className={`provenance-option${value === option.value ? ' is-active' : ''}`}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}
