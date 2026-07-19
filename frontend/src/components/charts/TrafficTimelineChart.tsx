import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import { SOURCE_TYPES, SOURCE_TYPE_LABEL, type SourceType } from '../../types/alert.ts'
import type { Provenance } from '../../types/filters.ts'
import type { TimelineBucket } from '../../types/stats.ts'
import { safeIso } from '../../utils/time.ts'

interface SeriesPoint {
  ts: number
  packets: number
}

/** Aggregate buckets into one packets-per-second series per source_type. */
function aggregate(buckets: TimelineBucket[]): Map<SourceType, SeriesPoint[]> {
  const perSource = new Map<SourceType, Map<number, number>>()
  for (const bucket of buckets) {
    let series = perSource.get(bucket.source_type)
    if (!series) {
      series = new Map()
      perSource.set(bucket.source_type, series)
    }
    series.set(bucket.bucket_ts, (series.get(bucket.bucket_ts) ?? 0) + bucket.packet_count)
  }
  const result = new Map<SourceType, SeriesPoint[]>()
  for (const [source, series] of perSource) {
    const points = [...series.entries()]
      .map(([ts, packets]) => ({ ts, packets }))
      .sort((a, b) => a.ts - b.ts)
    result.set(source, points)
  }
  return result
}

/**
 * Format one event-time value for an axis tick, tooltip label or the accessible
 * data table. Runtime validation accepts any FINITE bucket_ts, including finite
 * values outside JavaScript Date's representable range, so a live label must
 * never call `new Date(...).toISOString()` unguarded. A live value that Date can
 * represent shows a UTC wall-clock time; an unsupported finite value falls back
 * to raw event-time seconds. This never throws.
 */
function formatTick(source: SourceType, ts: number): string {
  if (source === 'live') {
    const iso = safeIso(ts)
    if (iso !== undefined) return iso.slice(11, 19)
    // Finite but outside Date's range: safe raw event-time-seconds fallback.
  }
  return `${ts.toFixed(0)}s`
}

/**
 * One provenance's timeline. Event-time axes are NOT comparable across
 * provenances, so each source is its own chart with its own X-axis (§3.2).
 */
function SingleTimeline({ source, points }: { source: SourceType; points: SeriesPoint[] }) {
  return (
    <div className="timeline-single" data-source={source}>
      <h4>
        {SOURCE_TYPE_LABEL[source]}{' '}
        <span className="muted">· {source === 'live' ? 'event time (UTC)' : 'event time (s)'}</span>
      </h4>
      <div className="chart chart-timeline" aria-hidden="true">
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={points} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
            <CartesianGrid strokeDasharray="2 3" />
            <XAxis
              dataKey="ts"
              tickLine={false}
              axisLine={false}
              minTickGap={28}
              tickFormatter={(value: number) => formatTick(source, value)}
            />
            <YAxis tickLine={false} axisLine={false} width={48} />
            <Tooltip labelFormatter={(label) => formatTick(source, Number(label))} />
            <Line
              type="monotone"
              dataKey="packets"
              stroke="currentColor"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only">
        <caption>{SOURCE_TYPE_LABEL[source]} traffic timeline (packets per event-time second)</caption>
        <thead>
          <tr>
            <th scope="col">Event time</th>
            <th scope="col">Packets</th>
          </tr>
        </thead>
        <tbody>
          {points.map((point) => (
            <tr key={point.ts}>
              <th scope="row">{formatTick(source, point.ts)}</th>
              <td>{point.packets}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function TrafficTimelineChart({
  buckets,
  provenance,
}: {
  buckets: TimelineBucket[]
  provenance: Provenance
}) {
  const series = aggregate(buckets)
  const sources =
    provenance === 'all'
      ? SOURCE_TYPES.filter((source) => series.has(source))
      : series.has(provenance)
        ? [provenance]
        : []

  return (
    <section className="chart-card" aria-label="Traffic timeline">
      <h3>Traffic timeline</h3>
      {sources.length === 0 ? (
        <p className="muted">No traffic recorded yet.</p>
      ) : provenance === 'all' ? (
        <>
          <p className="chart-note">
            Provenances use independent event-time axes and are shown as separate charts.
          </p>
          <div className="timeline-multiples">
            {sources.map((source) => (
              <SingleTimeline key={source} source={source} points={series.get(source) ?? []} />
            ))}
          </div>
        </>
      ) : (
        <SingleTimeline source={sources[0]} points={series.get(sources[0]) ?? []} />
      )}
    </section>
  )
}
