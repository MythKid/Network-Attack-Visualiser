import { SOURCE_TYPE_LABEL, type SourceType } from '../types/alert.ts'
import type { Provenance } from '../types/filters.ts'

/**
 * The persistent, unmissable traffic-source banner (AC2). Meaning is carried by
 * the TEXT label (SYNTHETIC / REPLAYED / LIVE-LAB), never by colour alone. In
 * "All" mode it lists the provenances actually present as text chips (§9).
 */
export function ProvenanceBanner({
  provenance,
  present,
}: {
  provenance: Provenance
  present: SourceType[]
}) {
  if (provenance !== 'all') {
    return (
      <div
        className={`provenance-banner provenance-${provenance}`}
        role="region"
        aria-label={`Traffic source: ${SOURCE_TYPE_LABEL[provenance]}`}
      >
        <span className="provenance-eyebrow">Traffic source</span>
        <strong className="provenance-label">{SOURCE_TYPE_LABEL[provenance]}</strong>
      </div>
    )
  }
  return (
    <div
      className="provenance-banner provenance-all"
      role="region"
      aria-label="Traffic source: all provenances"
    >
      <span className="provenance-eyebrow">Traffic sources</span>
      <strong className="provenance-label">ALL</strong>
      <span className="provenance-chips">
        {present.length === 0 ? (
          <span className="provenance-chip provenance-chip-empty">no traffic yet</span>
        ) : (
          present.map((source) => (
            <span key={source} className={`provenance-chip provenance-${source}`}>
              {SOURCE_TYPE_LABEL[source]}
            </span>
          ))
        )}
      </span>
    </div>
  )
}
