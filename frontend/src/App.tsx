import { useMemo, useState } from 'react'

import { AlertDetail } from './components/AlertDetail.tsx'
import { AlertTable } from './components/AlertTable.tsx'
import { DetectorBreakdown, SeverityBreakdown } from './components/Breakdowns.tsx'
import { Filters } from './components/Filters.tsx'
import { ProtocolDistributionChart } from './components/charts/ProtocolDistributionChart.tsx'
import { TrafficTimelineChart } from './components/charts/TrafficTimelineChart.tsx'
import { ProvenanceBanner } from './components/ProvenanceBanner.tsx'
import { ProvenanceSelector } from './components/ProvenanceSelector.tsx'
import { SummaryCards } from './components/SummaryCards.tsx'
import { ConnectionStatus, FreshnessBadge, LiveFeedStatus } from './components/StatusBadges.tsx'
import { EmptyState, ErrorState, LoadingState } from './components/states.tsx'
import { computePresentProvenances } from './state/presence.ts'
import { useStats } from './state/useStats.ts'
import { useSyncEngine } from './state/useSyncEngine.ts'
import type { Provenance, TableFilters } from './types/filters.ts'

export function App() {
  const { state, scope, setScope, retryData, retryConnection } = useSyncEngine()
  const stats = useStats(scope.provenance, state.reconnectNonce)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const present = useMemo(
    () => computePresentProvenances(stats.data, state.alerts),
    [stats.data, state.alerts],
  )
  const selectedAlert = useMemo(
    () => state.alerts.find((alert) => alert.alert_id === selectedId) ?? null,
    [state.alerts, selectedId],
  )

  const changeProvenance = (provenance: Provenance) => {
    setSelectedId(null)
    setScope({ ...scope, provenance })
  }
  const changeFilters = (filters: TableFilters) => {
    setSelectedId(null)
    setScope({ ...scope, filters })
  }

  const renderFeed = () => {
    if (state.alerts.length > 0) {
      return <AlertTable alerts={state.alerts} selectedId={selectedId} onSelect={setSelectedId} />
    }
    if (state.freshness === 'loading') return <LoadingState label="Loading alerts…" />
    if (state.freshness === 'error') {
      return <ErrorState message="Could not load alerts from the backend." onRetry={retryData} />
    }
    return <EmptyState>No alerts match the current scope.</EmptyState>
  }

  return (
    <div className="app">
      <a className="skip-link" href="#feed">
        Skip to alert feed
      </a>
      <header className="app-header">
        <div className="app-title">
          <h1>Network Attack Visualiser</h1>
          <p className="app-subtitle">Defensive lab dashboard · transparent heuristic detections</p>
        </div>
        <ProvenanceBanner provenance={scope.provenance} present={present} />
        <div className="app-status">
          <ConnectionStatus connection={state.connection} onRetry={retryConnection} />
          <FreshnessBadge freshness={state.freshness} />
        </div>
      </header>

      <div className="app-controls">
        <ProvenanceSelector value={scope.provenance} onChange={changeProvenance} />
        <Filters filters={scope.filters} onChange={changeFilters} />
      </div>

      <main className="app-main">
        <section className="overview" aria-label="Overview statistics">
          <div className="overview-header">
            <p className="provenance-wide-note">
              Statistics are provenance-wide — they are not affected by the severity, detector or
              category table filters.
            </p>
            {stats.stale && (
              <span className="stats-stale" role="status">
                Statistics may be stale — retrying…
              </span>
            )}
          </div>
          {stats.data ? (
            <SummaryCards totals={stats.data.totals} />
          ) : stats.error ? (
            <ErrorState message="Statistics are currently unavailable." />
          ) : (
            <LoadingState label="Loading statistics…" />
          )}
        </section>

        {stats.data && (
          <section className="charts-grid" aria-label="Traffic and alert charts">
            <ProtocolDistributionChart data={stats.data.protocol_distribution} />
            <TrafficTimelineChart
              buckets={stats.data.traffic_timeline}
              provenance={scope.provenance}
            />
            <SeverityBreakdown counts={stats.data.alerts_by_severity} />
            <DetectorBreakdown counts={stats.data.alerts_by_detector} />
          </section>
        )}

        <section className="feed" id="feed" aria-label="Alert feed">
          <div className="feed-main">
            <div className="feed-header">
              <h2>Live alert feed</h2>
              <LiveFeedStatus loaded={state.alerts.length} total={state.total} />
            </div>
            {renderFeed()}
          </div>
          <AlertDetail alert={selectedAlert} onClose={() => setSelectedId(null)} />
        </section>
      </main>

      <footer className="app-footer">
        <p className="muted">
          Heuristic detections are labelled as heuristics — confidence is capped and never asserted
          as certainty. Timestamps are logical event time; synthetic and replay values are shown as
          event-time seconds, never wall-clock-relative.
        </p>
      </footer>
    </div>
  )
}
